// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _QUICSOCK_SERVER_SESSION_
#define _QUICSOCK_SERVER_SESSION_

#include <stdint.h>
#include <map>

#include "base/macros.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_protocol.h"

#include "quicsock/quicsock_session.h"
#include "quicsock/quicsock_observer.h"
#include "quicsock/server/quicsock_server_session_base.h"
#include "quicsock/quicsock_stream.h"
#include "quicsock/server/quicsock_server_session_visitor.h"

namespace net {

class QuicBlockedWriterInterface;
class QuicConfig;
class QuicConnection;
class QuicCryptoServerConfig;
class ReliableQuicStream;

namespace tools {

class QuicSockServerSession : public QuicSockServerSessionBase {
 public:
  QuicSockServerSession(const QuicConfig& config,
                          QuicConnection* connection,
                          QuicSockServerSessionVisitor* visitor,
                          const QuicCryptoServerConfig* crypto_config,
                          quicsock::QuicSockObserver *quicsock_observer);

  ~QuicSockServerSession() override;

 protected:
  // QuicSession methods:
  QuicSockStream* CreateIncomingDynamicStream(QuicStreamId id) override;
  QuicSockStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicSockServerSession);
};

} // namespace tools

}  // namespace net

#endif  // _QUICSOCK_SERVER_SESSION_
