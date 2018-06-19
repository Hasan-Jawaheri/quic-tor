// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/server/quicsock_server_session.h"

#include "base/logging.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_flags.h"
#include "net/quic/reliable_quic_stream.h"

#include "quicsock/quicsock_session.h"
#include "quicsock/quicsock_stream.h"

namespace net {
namespace tools {

QuicSockServerSession::QuicSockServerSession(
    const QuicConfig& config,
    QuicConnection* connection,
    QuicSockServerSessionVisitor* visitor,
    const QuicCryptoServerConfig* crypto_config,
    quicsock::QuicSockObserver *quicsock_observer)
    : QuicSockServerSessionBase(config, connection, visitor, crypto_config,
        quicsock_observer) {}

QuicSockServerSession::~QuicSockServerSession() {}

QuicCryptoServerStreamBase*
QuicSockServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config) {
  return new QuicCryptoServerStream(crypto_config, this);
}

QuicSockStream* QuicSockServerSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  if (!ShouldCreateIncomingDynamicStream(id)) {
    return nullptr;
  }

  QuicSockStream* stream = new QuicSockStream(id, this);
  return stream;
}

QuicSockStream* QuicSockServerSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!ShouldCreateOutgoingDynamicStream()) {
    return nullptr;
  }

  QuicStreamId id = GetNextOutgoingStreamId();
  QuicSockStream* stream = new QuicSockStream(id, this);
  stream->SetPriority(priority);
  ActivateStream(stream);

  return stream;
}

}  // namespace tools
}  // namespace net
