// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/quicsock_stream.h"

#include "base/logging.h"
#include "net/quic/quic_utils.h"

#include "quicsock/quicsock_session.h"

namespace net {

QuicSockStream::QuicSockStream(QuicStreamId id, QuicSockSession* session)
    : ReliableQuicStream(id, session),
      quicsock_session_(session),
      priority_(kDefaultPriority),
      visitor_(nullptr) {
  DCHECK_NE(kCryptoStreamId, id);
  quicsock_session_->RegisterStreamPriority(id, priority_);
}

QuicSockStream::~QuicSockStream() {
}

void QuicSockStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Processed " << iov.iov_len << " bytes for stream " << id();
    std::string str(static_cast<char*>(iov.iov_base), iov.iov_len);
    quicsock_session_->OnDataAvailable(str);

    sequencer()->MarkConsumed(iov.iov_len);
  }
  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();
}

// Must implement Priority since it is a pure virtual function in QuicSession.
SpdyPriority QuicSockStream::Priority() const {
  return priority_;
}

bool QuicSockStream::IsDoneReading() const {
  return sequencer()->IsClosed();
}

bool QuicSockStream::HasBytesToRead() const {
  return sequencer()->HasBytesToRead();
}

void QuicSockStream::SetPriority(SpdyPriority priority) {
  DCHECK_EQ(0u, stream_bytes_written());
  quicsock_session_->UpdateStreamPriority(id(), priority);
  priority_ = priority;
}

void QuicSockStream::OnClose() {
  ReliableQuicStream::OnClose();

  if (visitor_) {
    Visitor* visitor = visitor_;
    // Calling Visitor::OnClose() may result the destruction of the visitor,
    // so we need to ensure we don't call it again.
    visitor_ = nullptr;
    visitor->OnClose(this);
  }
}

ssize_t QuicSockStream::Writev(void *buf, size_t len, bool is_fin) {

  StringPiece data((const char*) buf, len);

  // TODO(kku): Expose QuicAckListenerInterface to caller instead of just
  // passing in nullptr.
  WriteOrBufferData(data, is_fin, nullptr);
  return len;
}

ssize_t QuicSockStream::Readv(const struct iovec* iov) {
  return quicsock_session_->Readv(iov);
}

}  // namespace net
