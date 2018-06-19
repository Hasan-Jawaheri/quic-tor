// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/client/quicsock_client_session.h"

#include "base/logging.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_server_id.h"

#include "quicsock/quicsock_stream.h"
#include "custom/proof_verifier_openssl.h"

using std::string;

namespace net {
namespace tools {

QuicSockClientSession::QuicSockClientSession(const QuicConfig& config,
    QuicConnection* connection, const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    quicsock::QuicSockObserver *quicsock_observer)
    : QuicSockClientSessionBase(connection, config, quicsock_observer),
      server_id_(server_id),
      crypto_config_(crypto_config),
      respect_goaway_(true) {}

QuicSockClientSession::~QuicSockClientSession() {}

void QuicSockClientSession::Initialize() {
  crypto_stream_.reset(CreateQuicCryptoStream());
  QuicSockClientSessionBase::Initialize();
}

void QuicSockClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void QuicSockClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

QuicSockStream* QuicSockClientSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!crypto_stream_->encryption_established()) {
    DVLOG(1) << "Encryption not active so no outgoing stream created.";
    return nullptr;
  }
  if (GetNumOpenOutgoingStreams() >= get_max_open_streams()) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already " << GetNumOpenOutgoingStreams() << " open.";
    return nullptr;
  }
  if (goaway_received() && respect_goaway_) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already received goaway.";
    return nullptr;
  }

  QuicStreamId id = GetNextOutgoingStreamId();
  QuicSockStream* stream = new QuicSockStream(id, this);
  stream->SetPriority(priority);
  ActivateStream(stream);

  return stream;
}

QuicSockClientCryptoStreamBase* QuicSockClientSession::GetCryptoStream() {
  return crypto_stream_.get();
}

void QuicSockClientSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

int QuicSockClientSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

bool QuicSockClientSession::ShouldCreateIncomingDynamicStream(
    QuicStreamId id) {
  if (!connection()->connected()) {
    LOG(DFATAL) << "ShouldCreateIncomingDynamicStream called when disconnected";
    return false;
  }

  if (id % 2 != 0) {
    DVLOG(1) << "Invalid incoming even stream_id:" << id;
    connection()->SendConnectionCloseWithDetails(
        QUIC_INVALID_STREAM_ID, "Server created odd numbered stream");
    return false;
  }
  return true;
}

QuicSockStream* QuicSockClientSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  if (!ShouldCreateIncomingDynamicStream(id)) {
    return nullptr;
  }

  QuicSockStream* stream = new QuicSockStream(id, this);
  return stream;
}

QuicSockClientCryptoStreamBase* QuicSockClientSession::CreateQuicCryptoStream() {
  return new QuicSockClientCryptoStream(
      server_id_, this,
      new ProofVerifyContextOpenSSL(0),
      crypto_config_);
}

}  // namespace tools

}  // namespace net
