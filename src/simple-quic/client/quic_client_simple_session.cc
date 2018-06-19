// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic_client_simple_session.h"

#include "base/logging.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_server_id.h"

#include "quic_client_simple_stream.h"
#include "custom/proof_verifier_openssl.h"

using std::string;

namespace net {
namespace tools {

QuicClientSimpleSession::QuicClientSimpleSession(const QuicConfig& config,
                                     QuicConnection* connection,
                                     const QuicServerId& server_id,
                                     QuicCryptoClientConfig* crypto_config)
    : QuicClientSimpleSessionBase(connection, config),
      server_id_(server_id),
      crypto_config_(crypto_config),
      respect_goaway_(true) {}

QuicClientSimpleSession::~QuicClientSimpleSession() {}

void QuicClientSimpleSession::Initialize() {
  crypto_stream_.reset(CreateQuicCryptoStream());
  QuicClientSimpleSessionBase::Initialize();
}

void QuicClientSimpleSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void QuicClientSimpleSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

QuicClientSimpleStream* QuicClientSimpleSession::CreateOutgoingDynamicStream(
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
  QuicClientSimpleStream* stream = CreateClientStream();
  stream->SetPriority(priority);
  ActivateStream(stream);
  return stream;
}

QuicClientSimpleStream* QuicClientSimpleSession::CreateClientStream() {
  return new QuicClientSimpleStream(GetNextOutgoingStreamId(), this);
}

QuicCryptoClientSimpleStreamBase* QuicClientSimpleSession::GetCryptoStream() {
  return crypto_stream_.get();
}

void QuicClientSimpleSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

int QuicClientSimpleSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

QuicSimpleStream* QuicClientSimpleSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  DLOG(ERROR) << "Server push not supported";
  return nullptr;
}

QuicCryptoClientSimpleStreamBase* QuicClientSimpleSession::CreateQuicCryptoStream() {
  return new QuicCryptoClientSimpleStream(
      server_id_, this,
      new ProofVerifyContextOpenSSL(0),
      crypto_config_);
}

}  // namespace tools

}  // namespace net
