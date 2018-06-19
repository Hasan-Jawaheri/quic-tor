#include "quicsock.h"
#include "quicsock_internal.h"

#include <arpa/inet.h>
#include <event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "net/base/ip_endpoint.h"
#include "net/base/ip_address_number.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_utils.h"

#include "quicsock/client_event_thread.h"
#include "quicsock/eventfd_util.h"
#include "quicsock/server_event_thread.h"
#include "quicsock/socket_event_thread.h"

// TODO(kku): exit_manager should be declared on the top-level stack so it can
// call all registered callbacks and singleton destructors as it goes not of
// scope.
static base::AtExitManager exit_manager;

// Internal state of the module.
typedef struct {
   // Path to PEM-encoded certificate file.
  std::string cert_path;
   // Path to PEM-encoded private key file.
  std::string key_path;
} quicsock_state_s;

static quicsock_state_s quicsock_state;

void qs_init(const char *cert_path, const char *key_path) {
  quicsock_state.cert_path = std::string(cert_path);
  quicsock_state.key_path = std::string(key_path);

  // Set up logging.
  // We need to init CommandLine first as a hack since
  // logging::BaseInitLoggingImpl expects command line to be processed.
  base::CommandLine::Init(0, nullptr);

  logging::LoggingSettings settings;
  int min_log_level = 0;

#ifdef NDEBUG
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  min_log_level = 0;
#else
  char logName[256];
  snprintf(logName, 256, "/tmp/quicsock.log.%d", getpid());

  settings.logging_dest = logging::LOG_TO_ALL;
  settings.log_file = logName;
  settings.lock_log = logging::LOCK_LOG_FILE;
  settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  min_log_level = -1;
#endif // NDEBUG

  CHECK(logging::InitLogging(settings));
  logging::SetMinLogLevel(min_log_level);
  logging::SetLogItems(/*enable_process_id=*/ true, /*enable_thread_id=*/ true,
      /*enable_timestamp=*/ true, /*enable_tickcount=*/ true);
}

quicsock_t qs_open() {
  quicsock_t qs = (quicsock_t) malloc(sizeof(quicsock_internal_s));
  if (qs == NULL) {
    LOG(ERROR) << "Cannot malloc new quicsock_t";
    return INVALID_QUICSOCK;
  }

  qs->type = QUICSOCK_UNKNOWN;
  qs->bind_address = nullptr;
  qs->event_thread = nullptr;
  qs->connID = -1;
  qs->eventfd = -1;

  DVLOG(1) << "qs_open";
  return qs;
}

void qs_close(quicsock_t qs) {
  if (qs == INVALID_QUICSOCK)
    return;

  DVLOG(1) << "qs_close " << qs_get_id(qs);

  delete qs->bind_address;

  // TODO(kku): Stop event thread if this is a client or listening server.

  // TODO(kku): Free qs.

  // TODO(kku): Tell event_thread to clsoe session represented by connID. Make
  // sure we drain the SendQueue first.
}

int qs_bind(quicsock_t qs, const struct sockaddr *addr, socklen_t addrlen) {
  if (qs == INVALID_QUICSOCK) {
    return -1;
  }

  // We should not be binding a client socket or an existing server socket.
  DVLOG(1) << "qs_bind";

  net::IPEndPoint *endpoint = new net::IPEndPoint();
  if (endpoint == nullptr) {
    LOG(ERROR) << "Failed to allocate IPEndPoint";
    return -1;
  }

  if (!endpoint->FromSockAddr(addr, addrlen)) {
    LOG(ERROR) << "Failed to get IPEndPoint";
    delete endpoint;
    return -1;
  }

  if (qs->bind_address != nullptr)
    delete qs->bind_address;

  qs->bind_address = endpoint;
  return 0;
}

int qs_listen(quicsock_t qs) {
  if (qs == INVALID_QUICSOCK) {
    return -1;
  }
  if (qs->bind_address == nullptr) {
    LOG(ERROR) << "Listen without binding address";
    return -1;
  }

  DVLOG(1) << "qs_listen";

  // By listening, we are effectively creating a server.
  quicsock::ServerEventThread *event_thread = new quicsock::ServerEventThread(
      quicsock_state.cert_path, quicsock_state.key_path);
  if (event_thread == nullptr) {
    LOG(ERROR) << "Failed to create ServerEventThread";
    return -1;
  }
  if (!event_thread->Initialize()) {
    LOG(ERROR) << "Failed to initialize ServerEventThread";
    delete event_thread;
    return -1;
  }

  if (!event_thread->Listen(qs->bind_address)) {
    delete event_thread;
    return -1;
  }

  qs->type = QUICSOCK_SERVER_LISTEN;
  qs->eventfd = event_thread->GetAcceptEventFD();
  DCHECK(qs->eventfd >= 0);
  qs->event_thread = static_cast<quicsock::SocketEventThread*>(event_thread);

  qs->event_thread->WaitForEvents();
  return 0;
}

quicsock_t qs_accept(quicsock_t qs, struct sockaddr *peer, socklen_t *addrlen) {
  if (qs == INVALID_QUICSOCK) {
    LOG(ERROR) << "Cannot accept on an invalid quicsock";
    return INVALID_QUICSOCK;
  }
  if (qs->type != QUICSOCK_SERVER_LISTEN) {
    LOG(ERROR) << "Cannot accept on a non listening server quicsock";
    return INVALID_QUICSOCK;
  }

  DVLOG(1) << "qs_accept";

  quicsock_t new_qs = (quicsock_t) malloc(sizeof(quicsock_internal_s));
  if (new_qs == NULL) {
    LOG(ERROR) << "Failed to malloc quicsock_t for accept";
    return INVALID_QUICSOCK;
  }
  
  DCHECK(qs->event_thread != nullptr);
  quicsock::ServerEventThread *server_event_thread =
      reinterpret_cast<quicsock::ServerEventThread*>(qs->event_thread);
  new_qs->eventfd = server_event_thread->Accept(&new_qs->connID, peer, addrlen);
  if (new_qs->eventfd < 0) {
    LOG(ERROR) << "Accept failed";
    free(new_qs);
    return INVALID_QUICSOCK;
  }

  new_qs->type = QUICSOCK_SERVER_ACCEPT;
  new_qs->event_thread = qs->event_thread;

  return new_qs;
}

int qs_connect(quicsock_t qs, const struct sockaddr *dst_addr,
    socklen_t addrlen) {
  if (qs == INVALID_QUICSOCK) {
    return -1;
  }

  DVLOG(1) << "qs_connect";

  net::IPEndPoint endpoint;
  if (!endpoint.FromSockAddr(dst_addr, addrlen)) {
    LOG(ERROR) << "Failed to get IPEndPoint";
    return -1;
  }

  // By calling connect, we are effectively creating a client.
  quicsock::ClientEventThread *event_thread = new quicsock::ClientEventThread();
  if (event_thread == nullptr) {
    LOG(ERROR) << "Failed to allocate ClientEventThread";
    return -1;
  }

  if (!event_thread->Initialize()) {
    LOG(ERROR) << "Failed to initialize ClientEventThread";
    delete event_thread;
    return -1;
  }

  // TODO(kku): Pass in bind address to connect.
  qs->eventfd = event_thread->Connect(endpoint, &qs->connID);
  if (qs->eventfd < 0) {
    delete event_thread;
    return -1;
  }

  qs->type = QUICSOCK_CLIENT;
  qs->event_thread = static_cast<quicsock::ClientEventThread*>(event_thread);

  DVLOG(1) << "qs_connect complete eventfd=" << qs->eventfd
      << " conn=" << qs->connID;

  qs->event_thread->WaitForEvents();
  return 0;
}

ssize_t qs_send(quicsock_t qs, void *buf, size_t len,
    quicsock_stream_id_t user_stream_id) {
  if (qs == INVALID_QUICSOCK || qs->type == QUICSOCK_UNKNOWN ||
      qs->type == QUICSOCK_SERVER_LISTEN) {
    LOG(ERROR) << "Tried to send on invalid quicsock";
    return -1;
  }

  DVLOG(1) << "qs_send fd=" << qs->eventfd << " buf_len=" << len;

  return qs->event_thread->Send(qs->connID, buf, len, user_stream_id);
}

ssize_t qs_recv(quicsock_t qs, void *buf, size_t len) {
  if (qs == INVALID_QUICSOCK || qs->type == QUICSOCK_UNKNOWN ||
      qs->type == QUICSOCK_SERVER_LISTEN) {
    return -1;
  }

  DVLOG(1) << "qs_recv fd=" << qs->eventfd << " buf_len=" << len;
  
  return qs->event_thread->Recv(qs->connID, buf, len);
}

uint64_t qs_get_id(quicsock_t qs) {
  if (qs == INVALID_QUICSOCK || qs->type == QUICSOCK_UNKNOWN)
    return 0;

  if (qs->type == QUICSOCK_SERVER_LISTEN)
    return 0;

  return qs->connID;
}

int qs_get_fd(quicsock_t qs) {
  if (qs == INVALID_QUICSOCK)
    return -1;
  return qs->eventfd;
}
