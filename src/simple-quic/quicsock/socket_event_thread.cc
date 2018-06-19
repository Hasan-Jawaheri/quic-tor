#include <errno.h>
#include <event.h>
#include <stdlib.h>

#include "base/logging.h"

#include "quicsock/eventfd_util.h"
#include "quicsock/socket_event_thread.h"
#include "quicsock/libevent_handler.h"

namespace quicsock {

static void *DummyStart(void *arg) {
  SocketEventThread *thread = (SocketEventThread*) arg;
  DCHECK(thread != nullptr);
  thread->WorkerThreadStart();
  return NULL;
}

// libevent callbacks
static void OnUDPSocketEvent(int fd, short int event_type, void *arg) {
  SocketEventThread *thread = (SocketEventThread*) arg;
  DCHECK(thread != nullptr);

  if (event_type & EV_READ) {
    thread->OnCanRead(fd);
  } else if (event_type & EV_WRITE) {
    thread->OnCanWrite(fd);
  }

  // Check if we want to exit the event loop.
  thread->MaybeExitEventLoop();
}

static void OnSendQueueEvent(int fd, short int event_type, void *arg) {
  SocketEventThread *thread = (SocketEventThread*) arg;
  DCHECK(thread != nullptr);

  // We have something to send.
  thread->HandleSendQueueEvent();
}

SocketEventThread::QueuedSendBuffer::QueuedSendBuffer(
    net::QuicConnectionId conn_id, quicsock_stream_id_t stream_id, void *buf,
    size_t len, volatile bool *done)
    : conn_id_(conn_id),
      stream_id_(stream_id),
      buf_(buf),
      buf_len_(len),
      done_(done),
      return_value_(-1) {}

SocketEventThread::QueuedSendBuffer::~QueuedSendBuffer() {
}

SocketEventThread::SocketEventThread()
    : initialized_(false),
      fd_(-1),
      event_handler_(nullptr),
      base_(nullptr),
      worker_thread_running_(false),
      stop_waiting_received_(false),
      send_queue_eventfd_(-1) {}

SocketEventThread::~SocketEventThread() {
  if (!initialized_)
    return;

  // Wait for the worker thread to finish.
  if (worker_thread_running_)
    StopWaiting();

  DCHECK(event_handler_ != nullptr);
  event_handler_->CancelAllAlarms();
  delete event_handler_;

  event_base_free(base_);

  // Clear send queue
  SendQueue::iterator send_queue_it;
  for (send_queue_it = send_queue_.begin();
      send_queue_it != send_queue_.end();
      send_queue_it++) {
    delete *send_queue_it;
  }
  send_queue_.clear();
  close(send_queue_eventfd_);

  // Close all sessions.
  SessionMap::iterator session_it;
  for (session_it = session_map_.begin();
      session_it != session_map_.end();
      session_it++) {
    // TODO(kku): Verify close session behavior.
    delete session_it->second;
  }
  session_map_.clear();

  if (pthread_mutex_destroy(&session_map_mutex_) != 0) {
    LOG(ERROR) << "Failed to destroy session_map_mutex_";
  }
  if (pthread_mutex_destroy(&send_queue_mutex_) != 0) {
    LOG(ERROR) << "Failed to destroy send_queue_mutex_";
  }
}

bool SocketEventThread::Initialize() {
  if (initialized_)
    return true;

  base_ = event_base_new();
  if (base_ == NULL) {
    LOG(ERROR) << "Unable to create event base";
    return false;
  }

  send_queue_eventfd_ = CreateEventFD();
  if (send_queue_eventfd_ < 0) {
    LOG(ERROR) << "Failed to create send_queue_eventfd_";
    event_base_free(base_);
    return false;
  }

  if (pthread_mutex_init(&session_map_mutex_, NULL) != 0) {
    LOG(ERROR) << "Failed to initialize session_map mutex";
    event_base_free(base_);
    close(send_queue_eventfd_);
    return false;
  }

  if (pthread_mutex_init(&send_queue_mutex_, NULL) != 0) {
    LOG(ERROR) << "Failed to initialize send_queue_mutex_";
    event_base_free(base_);
    close(send_queue_eventfd_);
    pthread_mutex_destroy(&session_map_mutex_);
    return false;
  }

  LibEventHandler *handler = new LibEventHandler(base_);
  if (handler == nullptr) {
    LOG(ERROR) << "Unable to create event handler";
    event_base_free(base_);
    close(send_queue_eventfd_);
    pthread_mutex_destroy(&session_map_mutex_);
    pthread_mutex_destroy(&send_queue_mutex_);
    return false;
  }
  event_handler_ = handler;

  initialized_ = true;
  return true;
}

bool SocketEventThread::WaitForEvents() {
  if (!initialized_) {
    LOG(ERROR) << "Cannot WaitForEvents without initialization";
    return false;
  }
  if (fd_ < 0) {
    LOG(ERROR) << "Cannot wait on fd=" << fd_;
    return false;
  }
  if (worker_thread_running_) {
    LOG(ERROR) << "Worker thread is already running";
    return false;
  }

  if (pthread_create(&thread_, NULL, DummyStart, (void*) this) != 0) {
    LOG(ERROR) << "Failed to create worker thread: " << strerror(errno);
    return false;
  }

  worker_thread_running_ = true;
  return true;
}

void SocketEventThread::StopWaiting() {
  if (!initialized_) {
    LOG(ERROR) << "StopWaiting called on non-initialized SocketEventThread";
    return;
  }
  if (!worker_thread_running_) {
    LOG(WARNING) << "StopWaiting called when no worker thread is running";
    return;
  }

  DVLOG(1) << "Stop waiting received for fd=" << fd_;
  stop_waiting_received_ = true;

  // Wait for worker thread to stop.
  if (pthread_join(thread_, NULL) != 0) {
    LOG(ERROR) << "Failed to join worker thread";
  }

  DVLOG(1) << "Worker thread stoppeed";
  worker_thread_running_ = false;
}

void SocketEventThread::WorkerThreadStart() {
  DVLOG(1) << "SocketEventThread started for fd=" << fd_;

  DCHECK(base_ != nullptr);
  DCHECK(event_handler_ != nullptr);
  DCHECK(fd_ != -1);

  // Add UDP socket event.
  // Make sure we are waiting for timeout events to periodically check
  // whether we should exit the event loop.
  int udp_event_flags = EV_READ|EV_WRITE|EV_TIMEOUT|EV_PERSIST|EV_ET;
  struct event *udp_sock_event = event_new(base_, fd_, udp_event_flags,
      OnUDPSocketEvent, (void*) this);
  struct timeval timeout = {0, 50 * 1000}; // 50 * 1000 us suggested by Quic.
  DCHECK(udp_sock_event != nullptr);
  event_add(udp_sock_event, &timeout);

  // Add SendQueue event.
  DCHECK(send_queue_eventfd_ != -1);
  int send_queue_event_flags = EV_READ|EV_PERSIST|EV_ET;
  struct event *send_queue_event = event_new(base_, send_queue_eventfd_,
      send_queue_event_flags, OnSendQueueEvent, (void*) this);
  DCHECK(send_queue_event != nullptr);
  event_add(send_queue_event, NULL);

  DVLOG(1) << "SocketEventThead dispatching base (fd=" << fd_ << ") ";
  event_base_dispatch(base_);

  DVLOG(1) << "SocketEventThread event loop returned (fd=" << fd_ << ")";
  event_del(udp_sock_event);
  event_free(udp_sock_event);
  event_del(send_queue_event);
  event_free(send_queue_event);

  DCHECK(stop_waiting_received_);
}

void SocketEventThread::MaybeExitEventLoop() {
  DCHECK(base_ != nullptr);

  bool should_exit = false;
  if (stop_waiting_received_) {
    DVLOG(1) << "Received stop waiting, exiting event loop";
    should_exit = true;
  }

  if (should_exit)
    event_base_loopbreak(base_);
}

void SocketEventThread::HandleSendQueueEvent() {
  // Since we are using edge-triggered events, we must loop until we get
  // the pending writes.
  // TODO(kku): Does this starve the UDP events?
  while (RemoveEventFromEventFD(send_queue_eventfd_)) {
    pthread_mutex_lock(&send_queue_mutex_);
    DCHECK(!send_queue_.empty());
    QueuedSendBuffer *buf = send_queue_.front();
    send_queue_.pop_front();
    pthread_mutex_unlock(&send_queue_mutex_);

    DCHECK(buf != nullptr);
    net::QuicConnectionId id = buf->GetConnID();
    DVLOG(1) << "Handling queued send for conn=" << id;

    pthread_mutex_lock(&session_map_mutex_);

    SessionMap::iterator it = session_map_.find(id);
    DCHECK(it != session_map_.end());

    ssize_t ret = SendImpl(it->second, buf->GetBuf(), buf->GetBufLen(),
        buf->GetStreamID());

    pthread_mutex_unlock(&session_map_mutex_);

    buf->SetReturnValue(ret);
    buf->MarkAsDone();
    DVLOG(1) << "Finished queued send for conn=" << id;

    // We don't need to free buf since the send is blocking. The user will free
    // it.
  }
}

ssize_t SocketEventThread::Send(net::QuicConnectionId id, void *buf, size_t len,
    quicsock_stream_id_t user_stream_id) {
  DCHECK(initialized_);

  DVLOG(1) << "Send on conn=" << id;

  if (buf == nullptr) {
    LOG(ERROR) << "Send with NULL buffer";
    return -1;
  }

  if (len == 0) {
    return 0;
  }

  volatile bool done = false;
  QueuedSendBuffer send_buf(id, user_stream_id, buf, len, &done);

  pthread_mutex_lock(&send_queue_mutex_);
  send_queue_.push_back(&send_buf);
  pthread_mutex_unlock(&send_queue_mutex_);

  // Let the event thread know that there's something in send_queue_.
  AddEventToEventFD(send_queue_eventfd_);

  // Blocking send.
  // TODO(kku): We are assuming we are on multi-core processors, so we spin
  // wait.
  while (!done) {
    // Wait, do nothing
  }

  DVLOG(1) << "Send complete for conn=" << id;
  return send_buf.GetReturnValue();
}

ssize_t SocketEventThread::Recv(net::QuicConnectionId id, void *buf,
    size_t len) {
  DCHECK(initialized_);

  if (buf == nullptr) {
    LOG(ERROR) << "Recv with NULL buffer";
    return -1;
  }

  if (len == 0)
    return 0;

  pthread_mutex_lock(&session_map_mutex_);
  SessionMap::iterator it = session_map_.find(id);
  if (it == session_map_.end()) {
    LOG(ERROR) << "Cannot find session for " << id;
    pthread_mutex_unlock(&session_map_mutex_);
    return -1;
  }

  ssize_t ret = RecvImpl(it->second, buf, len);

  // We cannot unlock before this point because we need to make sure the
  // session is not freed while we're reading from it.
  pthread_mutex_unlock(&session_map_mutex_);

  return ret;
}

void SocketEventThread::OnCanRead(int fd) {
  OnCanReadImpl(fd);
}

void SocketEventThread::OnCanWrite(int fd) {
  OnCanWriteImpl(fd);
}

void SocketEventThread::OnNewSession(net::QuicConnectionId id,
    net::QuicSockSession* session) {
  DCHECK(initialized_);
  DCHECK(session != nullptr);

  DVLOG(1) << "QuicSock adding new session (conn=" << id << ")";

  pthread_mutex_lock(&session_map_mutex_);
  session_map_.insert(std::make_pair(id, session));
  pthread_mutex_unlock(&session_map_mutex_);

  OnNewSessionImpl(id, session);
}

void SocketEventThread::OnConnectionClosed(net::QuicConnectionId id,
        net::QuicSockSession *session, bool from_peer) {
  DVLOG(1) << "QuicSock connection " << id << " closed";

  // TODO(kku): Remove from session_map_?

  OnConnectionClosedImpl(id, session, from_peer);
}

ssize_t SocketEventThread::SendImpl(net::QuicSockSession *session, void *buf,
    size_t len, quicsock_stream_id_t user_stream_id) {
  DCHECK(session != nullptr);
  DCHECK(buf != nullptr);

  if (len == 0) {
    return 0;
  }

  // We are not allowing the client to send data before handshake is complete.
  // Look at SendRequest in QuicSockClient.

  if (session->connection() == nullptr ||
      !session->connection()->connected()) {
    DVLOG(1) << "Connection " << session->connection()->connection_id()
      << " is not connected, cannot send";
    return -1;
  }

  net::QuicConnectionId connID = session->connection()->connection_id();

  net::QuicSockStream *stream = session->GetOrCreateOutgoingStream(
      user_stream_id);

  if (stream == nullptr) {
    DVLOG(1) << "Cannot find stream for connection " << connID;
    return -1;
  }

  DVLOG(1) << "Sending to connection " << connID << " stream " << stream->id();

  return stream->Writev(buf, len, /*is_fin=*/ false);
}

ssize_t SocketEventThread::RecvImpl(net::QuicSockSession *session, void *buf,
    size_t len) {
  DCHECK(session != nullptr);
  DCHECK(buf != nullptr);

  if (len == 0) {
    return 0;
  }

  if (session->connection() == nullptr) {
    LOG(ERROR) << "Recv on session without a connection";
    return -1;
  }

  net::QuicConnectionId connID = session->connection()->connection_id();
  DVLOG(1) << "Recv on connection " << connID;

  // Acknowledege the read on the eventfd.
  // Note that we don't expect the ack to always succeed because the user may
  // make multiple calls to Recv for each read event.
  // Read from eventfd should be atomic by POSIX standard.
  // TODO(kku): Move this into session.
  RemoveEventFromEventFD(session->GetEventFD());

  struct iovec input;
  input.iov_base = buf;
  input.iov_len = len;

  ssize_t bytes_read = session->Readv(&input);

  if (bytes_read == 0 && !session->PeerLeft()) {
    // Nothing read but peer is still around - the result of a previous read
    // consuming all the data received or the user program calling the recv in
    // a loop because the number of bytes read is the same size as their buffer.
    DVLOG(1) << "Recv returning -2 because there is nothing to read";
    bytes_read = -2;
  }

  DVLOG(1) << "Recv returning " << bytes_read;
  return bytes_read;
}

} // namespace quicsock
