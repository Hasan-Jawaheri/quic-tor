// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// TODO(kku): This is only needed for the test client/server. Should remove.

#include "server/quic_server_simple_stream.h"

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "net/quic/quic_flags.h"

#include "custom/quic_simple_session.h"
#include "custom/quic_simple_stream.h"

using base::StringPiece;
using base::StringToInt;
using std::string;

namespace net {
namespace tools {

QuicServerSimpleStream::QuicServerSimpleStream(QuicStreamId id,
                                               QuicSimpleSession* session)
    : QuicSimpleStream(id, session) {}

QuicServerSimpleStream::~QuicServerSimpleStream() {}

void QuicServerSimpleStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Server Processed " << iov.iov_len << " bytes for stream " << id();
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    sequencer()->MarkConsumed(iov.iov_len);
  }
  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  SendResponse();
}

void QuicServerSimpleStream::SendResponse() {
  // This is an echo stream.
  SendBody(body_);
}

void QuicServerSimpleStream::SendBody(StringPiece body) {
  /*
  // TODO(kku): Check if commeting out is ok.
  // We want to allow bi-directional streaming.
  if (!reading_stopped()) {
    StopReading();
  }
  */

  bool send_fin = true;
  DVLOG(1) << "Writing body with size: " << body.size();
  WriteOrBufferData(body, send_fin, nullptr);
  if (send_fin) {
    // Nothing else to send.
    return;
  }
}

}  // namespace tools
}  // namespace net
