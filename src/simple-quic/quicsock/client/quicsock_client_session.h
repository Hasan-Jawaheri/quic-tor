// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A client specific QuicSession subclass.

#ifndef NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_
#define NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_

#include <string>

#include "base/macros.h"
#include "net/quic/quic_protocol.h"

#include "quicsock/quicsock_observer.h"
#include "quicsock/client/quicsock_client_crypto_stream.h"
#include "quicsock/client/quicsock_client_session_base.h"
#include "quicsock/quicsock_stream.h"

namespace net {

class QuicConnection;
class QuicServerId;
class ReliableQuicStream;

namespace tools {

class QuicSockClientSession : public QuicSockClientSessionBase {
 public:
  QuicSockClientSession(const QuicConfig& config,
                    QuicConnection* connection,
                    const QuicServerId& server_id,
                    QuicCryptoClientConfig* crypto_config,
                    quicsock::QuicSockObserver *quicsock_observer);
  ~QuicSockClientSession() override;
  // Set up the QuicSockClientSession. Must be called prior to use.
  void Initialize() override;

  // QuicSession methods:
  QuicSockStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;
  QuicSockClientCryptoStreamBase* GetCryptoStream() override;

  // QuicSockClientSessionBase methods:
  void OnProofValid(const QuicCryptoClientConfig::CachedState& cached) override;
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override;

  // Performs a crypto handshake with the server.
  void CryptoConnect();

  // Returns the number of client hello messages that have been sent on the
  // crypto stream. If the handshake has completed then this is one greater
  // than the number of round-trips needed for the handshake.
  int GetNumSentClientHellos() const;

  void set_respect_goaway(bool respect_goaway) {
    respect_goaway_ = respect_goaway;
  }

 protected:
  // QuicSession methods:
  QuicSockStream* CreateIncomingDynamicStream(QuicStreamId id) override;

  // Create the crypto stream. Called by Initialize()
  virtual QuicSockClientCryptoStreamBase* CreateQuicCryptoStream();

  const QuicServerId& server_id() { return server_id_; }
  QuicCryptoClientConfig* crypto_config() { return crypto_config_; }

  bool ShouldCreateIncomingDynamicStream(QuicStreamId id);

 private:
  scoped_ptr<QuicSockClientCryptoStreamBase> crypto_stream_;
  QuicServerId server_id_;
  QuicCryptoClientConfig* crypto_config_;

  // If this is set to false, the client will ignore server GOAWAYs and allow
  // the creation of streams regardless of the high chance they will fail.
  bool respect_goaway_;

  DISALLOW_COPY_AND_ASSIGN(QuicSockClientSession);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_
