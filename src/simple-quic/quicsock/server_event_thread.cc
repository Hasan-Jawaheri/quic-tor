#include "base/logging.h"

#include "custom/proof_source_openssl.h"
#include "quicsock/eventfd_util.h"
#include "quicsock/server_event_thread.h"

namespace quicsock {

/**
 * @brief Creates a new ProofSource for server socket.
 * @param cert_path Path to PEM-encoded certificate.
 * @param key_path Path to PEM-encoded private key.
 * @return The ProofSource. On error, the CHECK will fail.
 */
static net::ProofSourceOpenSSL* create_proof_source(
    const std::string& cert_path, const std::string& key_path) {
  net::ProofSourceOpenSSL* proof_source = new net::ProofSourceOpenSSL();
  CHECK(proof_source->Initialize(cert_path, key_path, ""));
  return proof_source;
}

ServerEventThread::ServerEventThread(std::string& cert_path,
    std::string& key_path)
    : SocketEventThread(),
      cert_path_(cert_path),
      key_path_(key_path),
      server_(nullptr),
      accept_eventfd_(-1) {}

ServerEventThread::~ServerEventThread() {
  // Close unaccepted connections since the user does not know of their existence.
  // Note that it is up to the user to close accepted connections.
  pthread_mutex_lock(&unaccepted_sessions_mutex_);
  UnacceptedSessionSet::iterator it;
  for (it = unaccepted_sessions_.begin();
      it != unaccepted_sessions_.end(); ++it) {
    // TODO(kku): close connection
    // CloseConnection(*it);
  }
  pthread_mutex_unlock(&unaccepted_sessions_mutex_);

  CHECK_EQ(pthread_mutex_destroy(&unaccepted_sessions_mutex_), 0);

  if (accept_eventfd_ >= 0)
    close(accept_eventfd_);
  
  if (server_ != nullptr) {
    server_->Shutdown();
    delete server_;
  }
}

bool ServerEventThread::Initialize() {
  if (!SocketEventThread::Initialize())
    return false;

  if (pthread_mutex_init(&unaccepted_sessions_mutex_, NULL) != 0) {
    LOG(ERROR) << "Failed to init unaccepted_sessions_mutex_";
    return false;
  }

  return true;
}

bool ServerEventThread::Listen(net::IPEndPoint *bind_address) {
  if (cert_path_.empty() || key_path_.empty()) {
    LOG(ERROR) << "Cannot create QuicSock server without valid certificate "
        << " and key file";
    return false;
  }
  if (bind_address == nullptr) {
    LOG(ERROR) << "Cannot listen using an unbound socket";
    return false;
  }
  if (!initialized_) {
    LOG(ERROR) << "Cannot listen on uninitialized socket";
    return false;
  }

  net::QuicConfig config;
  server_ = new net::tools::QuicSockServer(
      create_proof_source(cert_path_, key_path_),
      config,
      net::QuicSupportedVersions(),
      this,
      event_handler_);
  server_->SetStrikeRegisterNoStartupPeriod();
  bool success = server_->Bind(*bind_address);
  if (!success) {
    delete server_;
    return false;
  }

  // Create new eventfd to represent the listening socket (connection 0).
  if (accept_eventfd_ >= 0)
    close(accept_eventfd_);
  accept_eventfd_ = CreateEventFD();
  if (accept_eventfd_ < 0) {
    server_->Shutdown();
    delete server_;
    return false;
  }

  success = server_->Listen();
  if (!success) {
    close(accept_eventfd_);
    server_->Shutdown();
    delete server_;
    return false;
  }

  // Set UDP fd.
  fd_ = server_->GetFD();
  DVLOG(1) << "Server opened UDP fd=" << fd_;
  
  return true;
}

int ServerEventThread::Accept(net::QuicConnectionId *connID,
    struct sockaddr *peer, socklen_t *addrlen) {
  if (!initialized_) {
    LOG(ERROR) << "Cannot accept on uninitialized socket";
    return -1;
  }
  if (server_ == nullptr) {
    LOG(ERROR) << "Cannot accept on null server";
    return -1;
  }
  if (connID == nullptr) {
    LOG(ERROR) << "Cannot accept without valid connID pointer";
    return -1;
  }

  // Acknowledege the read on the eventfd, making sure it's not the UDP fd.
  CHECK(RemoveEventFromEventFD(accept_eventfd_));

  // Find an "unaccepted" connection (from user's perspective) and return its
  // ID.
  pthread_mutex_lock(&unaccepted_sessions_mutex_);
  if (unaccepted_sessions_.empty()) {
    LOG(ERROR) << "No unaccepted connection";
    pthread_mutex_unlock(&unaccepted_sessions_mutex_);
    return -1;
  }

  net::QuicSockSession *session = *unaccepted_sessions_.begin();
  unaccepted_sessions_.erase(session);
  pthread_mutex_unlock(&unaccepted_sessions_mutex_);

  DVLOG(1) << "QuicSock accepted connection "
      << session->connection()->connection_id();

  *connID = session->connection()->connection_id();

  // Get the peer's address.
  if (peer != NULL) {
    const net::IPEndPoint peerAddress = session->connection()->peer_address();
    if (!peerAddress.ToSockAddr(peer, addrlen)) {
      LOG(ERROR) << "Failed to get peer address";
    }
  }

  return session->GetEventFD();
}

int ServerEventThread::GetAcceptEventFD() {
  if (!initialized_) {
    LOG(ERROR) << "Cannot get accept eventfd on uninitialized socket";
    return -1;
  }
  if (server_ == nullptr) {
    LOG(ERROR) << "Cannot get accept eventfd on null server";
    return -1;
  }

  return accept_eventfd_;
}

void ServerEventThread::OnCanReadImpl(int fd) {
  DCHECK(server_ != nullptr);
  DCHECK(fd == fd_); // we should only get events for UDP socket.
  server_->OnCanRead();
}

void ServerEventThread::OnCanWriteImpl(int fd) {
  DCHECK(server_ != nullptr);
  DCHECK(fd == fd_); // we should only get events for UDP socket.
  server_->OnCanWrite();
}

void ServerEventThread::OnNewSessionImpl(net::QuicConnectionId id,
    net::QuicSockSession* session) {
  pthread_mutex_lock(&unaccepted_sessions_mutex_);
  unaccepted_sessions_.insert(session);
  pthread_mutex_unlock(&unaccepted_sessions_mutex_);

  // Notify user of new connction to accept.
  AddEventToEventFD(accept_eventfd_);
}

void ServerEventThread::OnConnectionClosedImpl(net::QuicConnectionId id,
    net::QuicSockSession *session, bool from_peer) {
  // Remove the connection if it has not been accepted.
  pthread_mutex_lock(&unaccepted_sessions_mutex_);
  UnacceptedSessionSet::iterator it = unaccepted_sessions_.find(session);
  if (it != unaccepted_sessions_.end()) {
    unaccepted_sessions_.erase(session);

    // Remove the pending accept event.
    CHECK(RemoveEventFromEventFD(accept_eventfd_));
  }
  pthread_mutex_unlock(&unaccepted_sessions_mutex_);
}

} // namesapce quicsock
