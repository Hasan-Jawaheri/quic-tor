// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic_client_simple_stream.h"

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"

#include "quic_client_simple_session.h"

using base::StringPiece;
using std::string;
using base::StringToInt;

namespace net {
namespace tools {

QuicClientSimpleStream::QuicClientSimpleStream(QuicStreamId id,
                                           QuicClientSimpleSession* session)
    : QuicSimpleStream(id, session),
      allow_bidirectional_data_(true) {}

QuicClientSimpleStream::~QuicClientSimpleStream() {}

void QuicClientSimpleStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Client processed " << iov.iov_len << " bytes for stream "
             << id();
    data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    sequencer()->MarkConsumed(iov.iov_len);
  }
  if (sequencer()->IsClosed()) {
    OnFinRead();
  } else {
    sequencer()->SetUnblocked();
  }
}

size_t QuicClientSimpleStream::SendRequest(StringPiece body,
                                          bool fin) {
  size_t bytes_sent = body.size();

  if (!body.empty()) {
    WriteOrBufferData(body, fin, nullptr);
  }

  return bytes_sent;
}

void QuicClientSimpleStream::SendBody(const string& data, bool fin) {
  SendBody(data, fin, nullptr);
}

void QuicClientSimpleStream::SendBody(const string& data,
    bool fin,
    QuicAckListenerInterface* listener) {
  WriteOrBufferData(data, fin, listener);
}

}  // namespace tools
}  // namespace net
