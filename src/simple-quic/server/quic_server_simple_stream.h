// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// // Use of this source code is governed by a BSD-style license that can be
// // found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_SERVER_SIMPLE_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_SERVER_SIMPLE_STREAM_H_

#include <stddef.h>

#include <string>

#include "base/macros.h"
#include "net/quic/quic_protocol.h"

#include "custom/quic_simple_stream.h"
#include "net/quic/quic_framer.h"

namespace net {

namespace tools {

namespace test {
class QuicServerSimpleStreamPeer;
}  // namespace test

// All this does right now is aggregate data, and on fin, send an HTTP
// response.
class QuicServerSimpleStream : public QuicSimpleStream {
 public:
  QuicServerSimpleStream(QuicStreamId id, QuicSimpleSession* session);
  ~QuicServerSimpleStream() override;

  // ReliableQuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;

  // The response body of error responses.
  static const char* const kErrorResponseBody;

 protected:
  void Body(base::StringPiece body);

  const std::string& body() { return body_; }

 private:
  friend class test::QuicServerSimpleStreamPeer;

  void SendResponse();
  void SendBody(StringPiece body);

  // The parsed headers received from the client.
  std::string body_;

  DISALLOW_COPY_AND_ASSIGN(QuicServerSimpleStream);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SERVER_SIMPLE_STREAM_H_
