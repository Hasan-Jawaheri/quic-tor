// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku

#ifndef NET_QUIC_QUIC_CLIENT_SIMPLE_SESSION_BASE_H_
#define NET_QUIC_QUIC_CLIENT_SIMPLE_SESSION_BASE_H_

#include "base/macros.h"

#include "quicsock/quicsock_observer.h"
#include "quicsock/client/quicsock_client_crypto_stream.h"
#include "quicsock/quicsock_session.h"

namespace net {

// Base class for all client-specific QuicSession subclasses.
class NET_EXPORT_PRIVATE QuicSockClientSessionBase : public QuicSockSession {
 public:
  QuicSockClientSessionBase(QuicConnection* connection,
      const QuicConfig& config, quicsock::QuicSockObserver *quicsock_observer);

  ~QuicSockClientSessionBase() override;

  // Called when the proof in |cached| is marked valid.  If this is a secure
  // QUIC session, then this will happen only after the proof verifier
  // completes.
  virtual void OnProofValid(
      const QuicCryptoClientConfig::CachedState& cached) = 0;

  // Called when proof verification details become available, either because
  // proof verification is complete, or when cached details are used. This
  // will only be called for secure QUIC connections.
  virtual void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicSockClientSessionBase);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLIENT_SIMPLE_SESSION_BASE_H_
