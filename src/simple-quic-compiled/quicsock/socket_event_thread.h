#ifndef __SOCKET_EVENT_THREAD__
#define __SOCKET_EVENT_THREAD__

#include <event.h>
#include <pthread.h>
#include <stdint.h>

#include <list>
#include <map>

#include "quicsock/quicsock_event_handler.h"
#include "quicsock/quicsock_session.h"
#include "quicsock/server/quicsock_server.h"

// Thread to handle UDP socket events and invoke QUIC protocol.

namespace quicsock {

class SocketEventThread : public QuicSockObserver,
                          public QuicSockEventHandler::SocketCallback {
  public:
    SocketEventThread();
    virtual ~SocketEventThread();

    virtual bool Initialize();

    // Forks a new thread and waits for events on the given fd.
    // Returns false on error with no thread created.
    bool WaitForEvents();

    // Stop waiting for events. Returns after the worker thread has stopped.
    void StopWaiting();

    // Function for worker pthread.
    // Should only be called by pthread launch function.
    void WorkerThreadStart();

    // Exit the worker thread's event loop if StopWaiting has been called.
    // Should only be called from the worker thread.
    void MaybeExitEventLoop();

    void HandleSendQueueEvent();

    ssize_t Send(net::QuicConnectionId id, void *buf, size_t len,
        quicsock_stream_id_t user_stream_id);

    ssize_t Recv(net::QuicConnectionId id, void *buf, size_t len);

    // QuicSockObserver functions
    void OnNewSession(net::QuicConnectionId id,
        net::QuicSockSession* session) override;
    void OnConnectionClosed(net::QuicConnectionId id,
        net::QuicSockSession *session, bool from_peer) override;
        
    // QuicSockEventHandler::SocketCallback functions
    void OnCanRead(int fd) override;
    void OnCanWrite(int fd) override;

  protected:
    bool initialized_;

    // File descriptor we are monitoring.
    int fd_;

    // Event handler object for the Quic code to hook events into our event
    // base.
    QuicSockEventHandler *event_handler_;

    // For subclasses to implement.
    virtual void OnCanReadImpl(int fd) = 0;
    virtual void OnCanWriteImpl(int fd) = 0;
    virtual void OnNewSessionImpl(net::QuicConnectionId id,
        net::QuicSockSession* session) = 0;
    virtual void OnConnectionClosedImpl(net::QuicConnectionId id,
        net::QuicSockSession *session, bool from_peer) = 0;

  private:
    // TODO(kku): Make this more granular.
    // Requires session_map_mutex_ to be held throughout to ensure session is
    // not closed while sending.
    ssize_t SendImpl(net::QuicSockSession *session, void *buf, size_t len,
        quicsock_stream_id_t user_stream_id);

    // Requires session_map_mutex_ to be held throughout to ensure session is
    // not closed while receving.
    ssize_t RecvImpl(net::QuicSockSession *session, void *buf, size_t len);

    // The event base. Owned by us and used by the worker thread.
    struct event_base *base_;

    // The event processing pthread.
    pthread_t thread_;

    // Flag to indicate a worker thread is running.
    bool worker_thread_running_;

    // Flag to indicate that the worker should stop waiting.
    bool stop_waiting_received_;

    // Map QUIC connection ID to session. We don't own the session. It is up
    // to the user to free it.
    typedef std::map<net::QuicConnectionId, net::QuicSockSession*> SessionMap;
    SessionMap session_map_;

    // Mutex for session_map_. We need to synchronize because the event
    // thread will insert new sessions while the user will remove sessions.
    pthread_mutex_t session_map_mutex_;

    // Container for queued buffers that the user wants to send.
    class QueuedSendBuffer {
      public:
        QueuedSendBuffer(net::QuicConnectionId conn_id,
            quicsock_stream_id_t stream_id, void *buf, size_t len,
            volatile bool *done);
        ~QueuedSendBuffer();

        net::QuicConnectionId GetConnID() { return conn_id_; }
        quicsock_stream_id_t GetStreamID() { return stream_id_; }
        void *GetBuf() { return buf_; }
        size_t GetBufLen() { return buf_len_; }
        void SetReturnValue(ssize_t v) { return_value_ = v; }
        ssize_t GetReturnValue() { return return_value_; }
        void MarkAsDone() { *done_ = true; }

      private:
        net::QuicConnectionId conn_id_;
        quicsock_stream_id_t stream_id_;
        void *buf_;
        size_t buf_len_;
        volatile bool *done_;
        ssize_t return_value_;
    };

    // Queue to hold user buffers that they want to send.
    typedef std::list<QueuedSendBuffer*> SendQueue;
    SendQueue send_queue_;

    // Mutex to protect send_queue_.
    pthread_mutex_t send_queue_mutex_;

    // eventfd to signal there's something in the SendQueue.
    int send_queue_eventfd_;
};

} // namespace quicsock

#endif /* __SOCKET_EVENT_THREAD__ */
