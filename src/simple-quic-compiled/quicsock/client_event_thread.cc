#include "quicsock/client_event_thread.h"

#include "base/logging.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_utils.h"

#include "custom/proof_verifier_openssl.h"
#include "quicsock/eventfd_util.h"

namespace quicsock {

ClientEventThread::ClientEventThread()
    : SocketEventThread(),
      client_(nullptr),
      session_(nullptr) {}

ClientEventThread::~ClientEventThread() {
  // TODO(kku): Free session? Does client_->Disconnect free it? Does user free
  // it?
  if (client_ != nullptr) {
    client_->Disconnect();
    delete client_;
  }
}

int ClientEventThread::Connect(net::IPEndPoint& dst_addr,
    net::QuicConnectionId *connID) {
  if (!initialized_) {
    LOG(ERROR) << "Cannot call connected on uninitialized QuicSock";
    return -1;
  }
  if (connID == nullptr) {
    LOG(ERROR) << "Cannot connect with NULL connID";
    return -2;
  }
  DCHECK(event_handler_ != nullptr);

  DVLOG(1) << "Connecting to " << net::IPAddressToString(dst_addr.address())
      << " port " << dst_addr.port();

  net::QuicServerId server_id(net::IPAddressToString(dst_addr.address()),
      dst_addr.port(), net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::QuicSupportedVersions();

  /*
  // TODO(kku): For secure QUIC we need to verify the cert chain.
  scoped_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  if (line->HasSwitch("disable-certificate-verification")) {
    cert_verifier.reset(new FakeCertVerifier());
  }
  scoped_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  scoped_ptr<CTVerifier> ct_verifier(new MultiLogCTVerifier());
  ProofVerifierChromium* proof_verifier = new ProofVerifierChromium(
      cert_verifier.get(), nullptr, transport_security_state.get(),
      ct_verifier.get());
  */

  net::ProofVerifierOpenSSL* proof_verifier = new net::ProofVerifierOpenSSL();

  net::QuicConfig config;
  // Max idle time before crypto handshake.
  config.set_max_idle_time_before_crypto_handshake(
      net::QuicTime::Delta::FromSeconds(2));
  // Timeout for crypto handshake.
  config.set_max_time_before_crypto_handshake(
      net::QuicTime::Delta::FromSeconds(5));

  client_ = new net::tools::QuicSockClient(dst_addr, server_id,
      versions, config, event_handler_, proof_verifier, this);
  client_->set_initial_max_packet_length(net::kDefaultMaxPacketSize);

  if (!client_->Initialize()) {
    LOG(ERROR) << "Failed to initialize client.";
    // TODO(kku): Fix
    /*
    delete client_;
    client_ = nullptr;
    */
    return -3;
  }

  if (!client_->Connect()) {
    net::QuicErrorCode error = client_->session()->error();
    if (error == net::QUIC_INVALID_VERSION) {
      LOG(ERROR) << "Server talks QUIC, but none of the versions "
           << "supported by this client: "
           << QuicVersionVectorToString(versions);
    }
    LOG(ERROR) << "Failed to connect to " << dst_addr.port()
         << ". Error: " << net::QuicUtils::ErrorToString(error);
    // TODO(kku): Fix
    //delete client_;
    client_ = nullptr;
    return -4;
  }
  
  fd_ = client_->GetFD();
  session_ = client_->session();
  DCHECK(session_ != nullptr && session_->connection() != nullptr);
  *connID = session_->connection()->connection_id();

  // Note that our eventfd is automatically created when the connection is
  // established.
  return session_->GetEventFD();
}

void ClientEventThread::OnCanReadImpl(int fd) {
  DCHECK(client_ != nullptr);
  DCHECK(fd == fd_); // we should only get events for UDP socket.
  client_->OnCanRead(fd);
}

void ClientEventThread::OnCanWriteImpl(int fd) {
  DCHECK(client_ != nullptr);
  DCHECK(fd == fd_); // we should only get events for UDP socket.
  client_->OnCanWrite(fd);
}

void ClientEventThread::OnNewSessionImpl(net::QuicConnectionId id,
    net::QuicSockSession* session) {
  // Do nothing.
}

void ClientEventThread::OnConnectionClosedImpl(net::QuicConnectionId id,
    net::QuicSockSession *session, bool from_peer) {
  // Do nothing.
}

} // namesapce quicsock
