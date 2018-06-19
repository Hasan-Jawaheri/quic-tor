// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "server/quic_server_simple_session.h"

#include "base/logging.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flags.h"
#include "net/quic/reliable_quic_stream.h"

#include "custom/quic_simple_session.h"
#include "server/quic_server_simple_stream.h"

namespace net {
namespace tools {

QuicServerSimpleSession::QuicServerSimpleSession(
    const QuicConfig& config,
    QuicConnection* connection,
    QuicServerSimpleSessionVisitor* visitor,
    const QuicCryptoServerConfig* crypto_config)
    : QuicServerSimpleSessionBase(config, connection, visitor, crypto_config) {}

QuicServerSimpleSession::~QuicServerSimpleSession() {}

QuicCryptoServerStreamBase*
QuicServerSimpleSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config) {
  return new QuicCryptoServerStream(crypto_config, this);
}

QuicServerSimpleStream* QuicServerSimpleSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  if (!ShouldCreateIncomingDynamicStream(id)) {
    return nullptr;
  }

  return new QuicServerSimpleStream(id, this);
}

QuicServerSimpleStream* QuicServerSimpleSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!ShouldCreateOutgoingDynamicStream()) {
    return nullptr;
  }

  QuicServerSimpleStream* stream =
      new QuicServerSimpleStream(GetNextOutgoingStreamId(), this);
  stream->SetPriority(priority);
  ActivateStream(stream);
  return stream;
}

}  // namespace tools
}  // namespace net
