// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku

#ifndef NET_QUIC_QUIC_CLIENT_SIMPLE_SESSION_BASE_H_
#define NET_QUIC_QUIC_CLIENT_SIMPLE_SESSION_BASE_H_

#include "base/macros.h"

#include "client/quic_crypto_client_simple_stream.h"
#include "custom/quic_simple_session.h"

namespace net {

// Base class for all client-specific QuicSession subclasses.
class NET_EXPORT_PRIVATE QuicClientSimpleSessionBase : public QuicSimpleSession {
 public:
  QuicClientSimpleSessionBase(QuicConnection* connection, const QuicConfig& config);

  ~QuicClientSimpleSessionBase() override;

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
  DISALLOW_COPY_AND_ASSIGN(QuicClientSimpleSessionBase);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLIENT_SIMPLE_SESSION_BASE_H_
