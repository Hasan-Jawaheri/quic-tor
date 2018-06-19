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

#include "client/quic_crypto_client_simple_stream.h"
#include "quic_client_simple_session_base.h"
#include "quic_client_simple_stream.h"

namespace net {

class QuicConnection;
class QuicServerId;
class ReliableQuicStream;

namespace tools {

class QuicClientSimpleSession : public QuicClientSimpleSessionBase {
 public:
  QuicClientSimpleSession(const QuicConfig& config,
                    QuicConnection* connection,
                    const QuicServerId& server_id,
                    QuicCryptoClientConfig* crypto_config);
  ~QuicClientSimpleSession() override;
  // Set up the QuicClientSimpleSession. Must be called prior to use.
  void Initialize() override;

  // QuicSession methods:
  QuicClientSimpleStream* CreateOutgoingDynamicStream(
      SpdyPriority priority) override;
  QuicCryptoClientSimpleStreamBase* GetCryptoStream() override;

  // QuicClientSimpleSessionBase methods:
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
  QuicSimpleStream* CreateIncomingDynamicStream(QuicStreamId id) override;

  // Create the crypto stream. Called by Initialize()
  virtual QuicCryptoClientSimpleStreamBase* CreateQuicCryptoStream();

  // Unlike CreateOutgoingDynamicStream, which applies a bunch of sanity checks,
  // this simply returns a new QuicClientSimpleStream. This may be used by
  // subclasses which want to use a subclass of QuicClientSimpleStream for streams
  // but wish to use the sanity checks in CreateOutgoingDynamicStream.
  virtual QuicClientSimpleStream* CreateClientStream();

  const QuicServerId& server_id() { return server_id_; }
  QuicCryptoClientConfig* crypto_config() { return crypto_config_; }

 private:
  scoped_ptr<QuicCryptoClientSimpleStreamBase> crypto_stream_;
  QuicServerId server_id_;
  QuicCryptoClientConfig* crypto_config_;

  // If this is set to false, the client will ignore server GOAWAYs and allow
  // the creation of streams regardless of the high chance they will fail.
  bool respect_goaway_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientSimpleSession);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_CLIENT_SESSION_H_
