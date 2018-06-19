// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku

#ifndef NET_QUIC_QUIC_SIMPLE_SESSION_H_
#define NET_QUIC_QUIC_SIMPLE_SESSION_H_

#include <stddef.h>

#include "base/macros.h"
#include "net/quic/quic_session.h"

#include "quic_simple_stream.h"

namespace net {

// A QUIC session with a headers stream.
class NET_EXPORT_PRIVATE QuicSimpleSession : public QuicSession {
 public:
  QuicSimpleSession(QuicConnection* connection, const QuicConfig& config);

  ~QuicSimpleSession() override;

  void Initialize() override;

  // Called by the stream on SetPriority to update priority on the write blocked
  // list.
  void UpdateStreamPriority(QuicStreamId id, SpdyPriority new_priority);

  QuicSimpleStream* GetSimpleIncomingStream(const QuicStreamId stream_id);
  QuicSimpleStream* GetSimpleOutgoingStream();

 protected:
  // Override CreateIncomingDynamicStream() and CreateOutgoingDynamicStream()
  // with QuicSimpleStream return type to make sure that all data streams are
  // QuicSimpleStreams.
  QuicSimpleStream* CreateIncomingDynamicStream(QuicStreamId id) override = 0;
  QuicSimpleStream* CreateOutgoingDynamicStream(SpdyPriority priority) override =
      0;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicSimpleSession);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_SIMPLE_SESSION_H_
