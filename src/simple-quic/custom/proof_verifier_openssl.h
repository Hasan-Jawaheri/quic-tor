// Copyright 2013 The OpenSSL Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// TODO(kku): Implement

#ifndef NET_QUIC_CRYPTO_PROOF_VERIFIER_OPENSSL_H_
#define NET_QUIC_CRYPTO_PROOF_VERIFIER_OPENSSL_H_

#include <set>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"
/*
#include "net/cert/cert_verify_result.h"
#include "net/cert/ct_verify_result.h"
#include "net/cert/x509_certificate.h"
*/
#include "net/quic/crypto/proof_verifier.h"

namespace net {

class CertPolicyEnforcer;
class CertVerifier;
class CTVerifier;
class TransportSecurityState;

// ProofVerifyContextOpenSSL is the implementation-specific information that a
// ProofVerifierOpenSSL needs in order to log correctly.
struct ProofVerifyContextOpenSSL : public ProofVerifyContext {
  public:
    ProofVerifyContextOpenSSL(int cert_verify_flags)
      : cert_verify_flags(cert_verify_flags) {}

    int cert_verify_flags;
};

// ProofVerifierOpenSSL implements the QUIC ProofVerifier interface.
class NET_EXPORT_PRIVATE ProofVerifierOpenSSL : public ProofVerifier {
 public:
  ProofVerifierOpenSSL(CertVerifier* cert_verifier,
                       CertPolicyEnforcer* cert_policy_enforcer,
                       TransportSecurityState* transport_security_state,
                       CTVerifier* cert_transparency_verifier);
  // Dummy constructor to create a fake.
  ProofVerifierOpenSSL();
  ~ProofVerifierOpenSSL() override;

  // ProofVerifier interface
  QuicAsyncStatus VerifyProof(const std::string& hostname,
                              const std::string& server_config,
                              const std::vector<std::string>& certs,
                              const std::string& cert_sct,
                              const std::string& signature,
                              const ProofVerifyContext* verify_context,
                              std::string* error_details,
                              scoped_ptr<ProofVerifyDetails>* verify_details,
                              ProofVerifierCallback* callback) override;

 private:
  // Underlying verifier used to verify certificates.
  CertVerifier* const cert_verifier_;
  CertPolicyEnforcer* const cert_policy_enforcer_;

  TransportSecurityState* const transport_security_state_;
  CTVerifier* const cert_transparency_verifier_;

  DISALLOW_COPY_AND_ASSIGN(ProofVerifierOpenSSL);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_PROOF_VERIFIER_OPENSSL_H_
