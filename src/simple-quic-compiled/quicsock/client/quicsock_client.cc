// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/client/quicsock_client.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base/logging.h"
#include "net/base/net_util.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_data_reader.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_server_id.h"
#include "net/tools/quic/quic_default_packet_writer.h"
#include "net/tools/quic/quic_socket_utils.h"

#include "quicsock/quicsock_connection_helper.h"
#include "quicsock/client/quicsock_client_crypto_stream.h"

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

using std::string;
using std::vector;

namespace net {
namespace tools {

void QuicSockClient::ClientQuicDataToResend::Resend() {
  client_->SendRequest(body_, fin_);
}

QuicSockClient::QuicSockClient(IPEndPoint server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       quicsock::QuicSockEventHandler *event_handler,
                       ProofVerifier* proof_verifier,
                       quicsock::QuicSockObserver *quicsock_observer)
    : QuicSockClient(server_address,
                 server_id,
                 supported_versions,
                 QuicConfig(),
                 event_handler,
                 proof_verifier,
                 quicsock_observer) {}

QuicSockClient::QuicSockClient(IPEndPoint server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       const QuicConfig& config,
                       quicsock::QuicSockEventHandler *event_handler,
                       ProofVerifier* proof_verifier,
                       quicsock::QuicSockObserver *quicsock_observer)
    : QuicSockClientBase(server_id,
                        supported_versions,
                        config,
                        new QuicSockConnectionHelper(
                            new QuicClock(),
                            QuicRandom::GetInstance(),
                            event_handler),
                        proof_verifier,
                        quicsock_observer),
      server_address_(server_address),
      local_port_(0),
      fd_(-1),
      initialized_(false),
      packets_dropped_(0),
      overflow_supported_(false),
      event_handler_(event_handler) {}

QuicSockClient::~QuicSockClient() {
  if (connected()) {
    session()->connection()->SendConnectionCloseWithDetails(
        QUIC_PEER_GOING_AWAY, "Client being torn down");
  }

  STLDeleteElements(&data_to_resend_on_connect_);
  STLDeleteElements(&data_sent_before_handshake_);

  CleanUpUDPSocketImpl();
}

bool QuicSockClient::Initialize() {
  if (event_handler_ == nullptr)
    return false;

  QuicSockClientBase::Initialize();

  // If an initial flow control window has not explicitly been set, then use the
  // same values that Chrome uses.
  const uint32_t kSessionMaxRecvWindowSize = 15 * 1024 * 1024;  // 15 MB
  const uint32_t kStreamMaxRecvWindowSize = 6 * 1024 * 1024;    //  6 MB
  if (config()->GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialStreamFlowControlWindowToSend(kStreamMaxRecvWindowSize);
  }
  if (config()->GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config()->SetInitialSessionFlowControlWindowToSend(
        kSessionMaxRecvWindowSize);
  }

  if (!CreateUDPSocket()) {
    return false;
  }

  initialized_ = true;
  return true;
}

QuicSockClient::QuicDataToResend::QuicDataToResend(StringPiece body,
                                               bool fin)
    : body_(body), fin_(fin) {}

QuicSockClient::QuicDataToResend::~QuicDataToResend() {}

bool QuicSockClient::CreateUDPSocket() {
  int address_family = server_address_.GetSockAddrFamily();
  fd_ = socket(address_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
  if (fd_ < 0) {
    LOG(ERROR) << "CreateSocket() failed: " << strerror(errno);
    return false;
  }

  int get_overflow = 1;
  int rc = setsockopt(fd_, SOL_SOCKET, SO_RXQ_OVFL, &get_overflow,
                      sizeof(get_overflow));
  if (rc < 0) {
    DLOG(WARNING) << "Socket overflow detection not supported";
  } else {
    overflow_supported_ = true;
  }

  if (!QuicSocketUtils::SetReceiveBufferSize(fd_,
                                             kDefaultSocketReceiveBuffer)) {
    return false;
  }

  if (!QuicSocketUtils::SetSendBufferSize(fd_, kDefaultSocketReceiveBuffer)) {
    return false;
  }

  rc = QuicSocketUtils::SetGetAddressInfo(fd_, address_family);
  if (rc < 0) {
    LOG(ERROR) << "IP detection not supported" << strerror(errno);
    return false;
  }

  if (bind_to_address_.size() != 0) {
    client_address_ = IPEndPoint(bind_to_address_, local_port_);
  } else if (address_family == AF_INET) {
    IPAddressNumber any4;
    CHECK(net::ParseIPLiteralToNumber("0.0.0.0", &any4));
    client_address_ = IPEndPoint(any4, local_port_);
  } else {
    IPAddressNumber any6;
    CHECK(net::ParseIPLiteralToNumber("::", &any6));
    client_address_ = IPEndPoint(any6, local_port_);
  }

  sockaddr_storage raw_addr;
  socklen_t raw_addr_len = sizeof(raw_addr);
  CHECK(client_address_.ToSockAddr(reinterpret_cast<sockaddr*>(&raw_addr),
                                   &raw_addr_len));
  rc =
      bind(fd_, reinterpret_cast<const sockaddr*>(&raw_addr), sizeof(raw_addr));
  if (rc < 0) {
    LOG(ERROR) << "Bind failed: " << strerror(errno);
    return false;
  }

  SockaddrStorage storage;
  if (getsockname(fd_, storage.addr, &storage.addr_len) != 0 ||
      !client_address_.FromSockAddr(storage.addr, storage.addr_len)) {
    LOG(ERROR) << "Unable to get self address.  Error: " << strerror(errno);
  }

  return true;
}

bool QuicSockClient::Connect() {
  DCHECK(event_handler_ != nullptr);

  // Attempt multiple connects until the maximum number of client hellos have
  // been sent.
  while (!connected() &&
         GetNumSentClientHellos() <= QuicSockClientCryptoStream::kMaxClientHellos) {
    StartConnect();
    while (EncryptionBeingEstablished()) {
      WaitForEvents();
    }
    if (FLAGS_enable_quic_stateless_reject_support && connected() &&
        !data_to_resend_on_connect_.empty()) {
      // A connection has been established and there was previously queued data
      // to resend.  Resend it and empty the queue.
      for (QuicDataToResend* data : data_to_resend_on_connect_) {
        data->Resend();
      }
      STLDeleteElements(&data_to_resend_on_connect_);
    }
    if (session() != nullptr &&
        session()->error() != QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      // We've successfully created a session but we're not connected, and there
      // is no stateless reject to recover from.  Give up trying.
      break;
    }
  }
  if (!connected() &&
      GetNumSentClientHellos() > QuicSockClientCryptoStream::kMaxClientHellos &&
      session() != nullptr &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    // The overall connection failed due too many stateless rejects.
    set_connection_error(QUIC_CRYPTO_TOO_MANY_REJECTS);
  }

  return session()->connection()->connected();
}

void QuicSockClient::StartConnect() {
  DCHECK(initialized_);
  DCHECK(!connected());

  QuicPacketWriter* writer = CreateQuicPacketWriter();

  DummyPacketWriterFactory factory(writer);

  if (connected_or_attempting_connect()) {
    // Before we destroy the last session and create a new one, gather its stats
    // and update the stats for the overall connection.
    UpdateStats();
    if (session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
      // If the last error was due to a stateless reject, queue up the data to
      // be resent on the next successful connection.
      // TODO(jokulik): I'm a little bit concerned about ordering here.  Maybe
      // we should just maintain one queue?
      DCHECK(data_to_resend_on_connect_.empty());
      data_to_resend_on_connect_.swap(data_sent_before_handshake_);
    }
  }

  CreateQuicSockClientSession(new QuicConnection(
      GetNextConnectionId(), server_address_, helper(), factory,
      /* owns_writer= */ false, Perspective::IS_CLIENT, supported_versions()));

  // Reset |writer_| after |session()| so that the old writer outlives the old
  // session.
  set_writer(writer);
  session()->Initialize();
  session()->CryptoConnect();
  set_connected_or_attempting_connect(true);
}

void QuicSockClient::Disconnect() {
  DCHECK(initialized_);

  if (connected()) {
    session()->connection()->SendConnectionCloseWithDetails(
        QUIC_PEER_GOING_AWAY, "Client disconnecting");
  }
  STLDeleteElements(&data_to_resend_on_connect_);
  STLDeleteElements(&data_sent_before_handshake_);

  CleanUpUDPSocket();

  initialized_ = false;
}

void QuicSockClient::CleanUpUDPSocket() {
  CleanUpUDPSocketImpl();
}

void QuicSockClient::CleanUpUDPSocketImpl() {
  if (fd_ > -1) {
    int rc = close(fd_);
    DCHECK_EQ(0, rc);
    fd_ = -1;
  }
}

void QuicSockClient::SendRequest(StringPiece body, bool fin) {
  QuicSockStream* stream = CreateReliableClientStream();
  if (stream == nullptr) {
    LOG(DFATAL) << "stream creation failed!";
    return;
  }
  stream->set_visitor(this);

  struct iovec input;
  input.iov_base = (void*) body.data();
  input.iov_len = body.length();
  stream->Writev(&input, 1, fin);

  if (FLAGS_enable_quic_stateless_reject_support) {
    // Record this in case we need to resend.
    auto data_to_resend = new ClientQuicDataToResend(body, fin, this);
    MaybeAddQuicDataToResend(data_to_resend);
  }
}

void QuicSockClient::MaybeAddQuicDataToResend(QuicDataToResend* data_to_resend) {
  DCHECK(FLAGS_enable_quic_stateless_reject_support);
  if (session()->IsCryptoHandshakeConfirmed()) {
    // The handshake is confirmed.  No need to continue saving requests to
    // resend.
    STLDeleteElements(&data_sent_before_handshake_);
    delete data_to_resend;
    return;
  }

  // The handshake is not confirmed.  Push the data onto the queue of data to
  // resend if statelessly rejected.
  data_sent_before_handshake_.push_back(data_to_resend);
}

bool QuicSockClient::WaitForEvents() {
  DCHECK(connected());

  DCHECK(event_handler_ != nullptr);
  // 50 * 1000 us is suggested by Quic.
  if (!event_handler_->WaitForSocketEvents(fd_, QS_EV_READ, 50 * 1000, this)) {
    LOG(FATAL) << "Failed to wait for socket events";
  }

  DCHECK(session() != nullptr);
  if (!connected() &&
      session()->error() == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT) {
    DCHECK(FLAGS_enable_quic_stateless_reject_support);
    DVLOG(1) << "Detected stateless reject while waiting for events.  "
             << "Attempting to reconnect.";
    Connect();
  }

  return session()->num_active_requests() != 0;
}

bool QuicSockClient::MigrateSocket(const IPAddressNumber& new_host) {
  if (!connected()) {
    return false;
  }

  CleanUpUDPSocket();

  bind_to_address_ = new_host;
  if (!CreateUDPSocket()) {
    return false;
  }

  session()->connection()->SetSelfAddress(client_address_);

  QuicPacketWriter* writer = CreateQuicPacketWriter();
  DummyPacketWriterFactory factory(writer);
  set_writer(writer);
  session()->connection()->SetQuicPacketWriter(writer, false);

  return true;
}

void QuicSockClient::OnClose(QuicSockStream* stream) {
}

QuicPacketWriter* QuicSockClient::CreateQuicPacketWriter() {
  return new QuicDefaultPacketWriter(fd_);
}

int QuicSockClient::ReadPacket(char* buffer,
                           int buffer_len,
                           IPEndPoint* server_address,
                           IPAddressNumber* client_ip) {
  return QuicSocketUtils::ReadPacket(
      fd_, buffer, buffer_len,
      overflow_supported_ ? &packets_dropped_ : nullptr, client_ip,
      server_address);
}

bool QuicSockClient::ReadAndProcessPacket() {
  // Allocate some extra space so we can send an error if the server goes over
  // the limit.
  char buf[2 * kMaxPacketSize];

  IPEndPoint server_address;
  IPAddressNumber client_ip;

  int bytes_read = ReadPacket(buf, arraysize(buf), &server_address, &client_ip);

  if (bytes_read < 0) {
    return false;
  }

  QuicEncryptedPacket packet(buf, bytes_read, false);

  IPEndPoint client_address(client_ip, client_address_.port());
  session()->connection()->ProcessUdpPacket(client_address, server_address,
                                            packet);
  return true;
}

void QuicSockClient::OnCanRead(int fd) {
  DCHECK_EQ(fd, fd_);
  while (connected() && ReadAndProcessPacket()) {
  }
}

void QuicSockClient::OnCanWrite(int fd) {
  DCHECK_EQ(fd, fd_);
  if (connected()) {
    writer()->SetWritable();
    session()->connection()->OnCanWrite();
  }
}

}  // namespace tools
}  // namespace net
