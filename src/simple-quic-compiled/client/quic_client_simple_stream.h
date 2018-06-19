// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_CLIENT_SIMPLE_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_CLIENT_SIMPLE_STREAM_H_

#include <stddef.h>
#include <sys/types.h>

#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_framer.h"

#include "custom/quic_simple_stream.h"

namespace net {
namespace tools {

class QuicClientSimpleSession;

class QuicClientSimpleStream : public QuicSimpleStream {
 public:
  QuicClientSimpleStream(QuicStreamId id, QuicClientSimpleSession* session);
  ~QuicClientSimpleStream() override;

  // ReliableQuicStream implementation called by the session when there's
  // data for us.
  void OnDataAvailable() override;

  // Returns the number of bytes sent.
  size_t SendRequest(base::StringPiece body,
                     bool fin);

  // Sends body data to the server, or buffers if it can't be sent immediately.
  void SendBody(const std::string& data, bool fin);

  // As above, but |delegate| will be notified once |data| is ACKed.
  void SendBody(const std::string& data, bool fin, QuicAckListenerInterface* listener);

  // Returns the response data.
  const std::string& data() { return data_; }

  void set_allow_bidirectional_data(bool value) {
    allow_bidirectional_data_ = value;
  }

  bool allow_bidirectional_data() const { return allow_bidirectional_data_; }

 private:
  // The parsed content-length, or -1 if none is specified.
  std::string data_;

  // When true allows the sending of a request to continue while the response is
  // arriving.
  bool allow_bidirectional_data_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientSimpleStream);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_SIMPLE_STREAM_H_
