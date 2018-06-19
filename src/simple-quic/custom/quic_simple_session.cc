// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic_simple_session.h"

#include "net/quic/quic_headers_stream.h"

namespace net {

QuicSimpleSession::QuicSimpleSession(QuicConnection* connection,
                                 const QuicConfig& config)
    : QuicSession(connection, config) {}

QuicSimpleSession::~QuicSimpleSession() {}

void QuicSimpleSession::Initialize() {
  QuicSession::Initialize();
}

QuicSimpleStream* QuicSimpleSession::GetSimpleIncomingStream(
    const QuicStreamId stream_id) {
  return static_cast<QuicSimpleStream*>(GetOrCreateDynamicStream(stream_id));
}

QuicSimpleStream* QuicSimpleSession::GetSimpleOutgoingStream() {
  return static_cast<QuicSimpleStream*>(CreateOutgoingDynamicStream(0));
}

void QuicSimpleSession::UpdateStreamPriority(QuicStreamId id,
                                          SpdyPriority new_priority) {
  // TODO(kku): Currently we are not registering streams, so calling
  // UpdateStreamPriority will throw an error.
  // write_blocked_streams()->UpdateStreamPriority(id, new_priority);
}

}  // namespace net
