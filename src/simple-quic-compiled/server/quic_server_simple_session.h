// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy server specific QuicSession subclass.

#ifndef NET_TOOLS_QUIC_QUIC_SERVER_SIMPLE_SESSION_H_
#define NET_TOOLS_QUIC_QUIC_SERVER_SIMPLE_SESSION_H_

#include <stdint.h>

#include <set>
#include <string>
#include <vector>

#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_protocol.h"

#include "custom/quic_simple_session.h"
#include "server/quic_server_simple_session_base.h"
#include "server/quic_server_simple_stream.h"

namespace net {

class QuicBlockedWriterInterface;
class QuicConfig;
class QuicConnection;
class QuicCryptoServerConfig;
class ReliableQuicStream;

namespace tools {

namespace test {
class QuicServerSimpleSessionPeer;
}  // namespace test

class QuicServerSimpleSession : public QuicServerSimpleSessionBase {
 public:
  QuicServerSimpleSession(const QuicConfig& config,
                          QuicConnection* connection,
                          QuicServerSimpleSessionVisitor* visitor,
                          const QuicCryptoServerConfig* crypto_config);

  ~QuicServerSimpleSession() override;

 protected:
  // QuicSession methods:
  QuicServerSimpleStream * CreateIncomingDynamicStream(QuicStreamId id) override;
  QuicServerSimpleStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config) override;

 private:
  friend class test::QuicServerSimpleSessionPeer;

  DISALLOW_COPY_AND_ASSIGN(QuicServerSimpleSession);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SERVER_SESSION_H_
