// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic_simple_stream.h"

#include "base/logging.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_write_blocked_list.h"

#include "quic_simple_session.h"

namespace net {

QuicSimpleStream::QuicSimpleStream(QuicStreamId id, QuicSimpleSession* session)
    : ReliableQuicStream(id, session),
      quic_session_(session),
      visitor_(nullptr) {
  DCHECK_NE(kCryptoStreamId, id);
}

QuicSimpleStream::~QuicSimpleStream() {
  if (!data_buffer_.empty()) {
    LOG(WARNING) << "Stream " << id() << " destroyed with " <<
        data_buffer_.size() << " unprocessed buffers" << std::endl;
    data_buffer_.clear();
  }
}

void QuicSimpleStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (sequencer()->GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Processed " << iov.iov_len << " bytes for stream " << id();
    std::string str(static_cast<char*>(iov.iov_base), iov.iov_len);
    data_buffer_.push_back(str);

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
SpdyPriority QuicSimpleStream::Priority() const {
  // TODO(kku): Return priority
  return 0;
}

bool QuicSimpleStream::IsDoneReading() const {
  return sequencer()->IsClosed();
}

bool QuicSimpleStream::HasBytesToRead() const {
  return sequencer()->HasBytesToRead();
}

ssize_t QuicSimpleStream::Writev(const struct iovec* iov,
    size_t iov_len, bool is_fin) {
  // TODO(kku): Expose QuicAckListenerInterface to caller instead of just
  // passing in nullptr.
  return WritevData(iov, iov_len, is_fin, nullptr).bytes_consumed;
}

ssize_t QuicSimpleStream::Readv(const struct iovec* iov) {
  size_t bytes_consumed = 0;
  size_t remaining_buf_size = iov->iov_len;

  while (!data_buffer_.empty() && remaining_buf_size > 0) {
    std::string data = data_buffer_.front();
    size_t bytes_to_consume = std::min(remaining_buf_size, data.length());

    char* base = (char*) iov->iov_base + bytes_consumed;
    memcpy(base, data.c_str(), bytes_to_consume);
    bytes_consumed += bytes_to_consume;
    remaining_buf_size -= bytes_to_consume;
    
    if (data.length() > bytes_to_consume) {
      CHECK(remaining_buf_size == 0);
      std::string remaining_data = data.substr(bytes_to_consume);
      data_buffer_.pop_front();
      data_buffer_.push_front(remaining_data);
    } else {
      data_buffer_.pop_front();
    }
  }

  CHECK(bytes_consumed <= iov->iov_len);
  return bytes_consumed;
}

void QuicSimpleStream::SetPriority(SpdyPriority priority) {
  DCHECK_EQ(0u, stream_bytes_written());
  quic_session_->UpdateStreamPriority(id(), priority);
  priority_ = priority;
}

void QuicSimpleStream::OnClose() {
  ReliableQuicStream::OnClose();

  if (visitor_) {
    Visitor* visitor = visitor_;
    // Calling Visitor::OnClose() may result the destruction of the visitor,
    // so we need to ensure we don't call it again.
    visitor_ = nullptr;
    visitor->OnClose(this);
  }
}

}  // namespace net
