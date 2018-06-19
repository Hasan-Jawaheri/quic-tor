// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "proof_verifier_openssl.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram_macros.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
// #include "crypto/signature_verifier.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
/*
#include "net/cert/asn1_util.h"
#include "net/cert/cert_policy_enforcer.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
*/
#include "net/log/net_log.h"
#include "net/quic/crypto/crypto_protocol.h"
// #include "net/ssl/ssl_config_service.h"

using base::StringPiece;
using base::StringPrintf;
using std::string;
using std::vector;

namespace net {

ProofVerifierOpenSSL::ProofVerifierOpenSSL(
    CertVerifier* cert_verifier,
    CertPolicyEnforcer* cert_policy_enforcer,
    TransportSecurityState* transport_security_state,
    CTVerifier* cert_transparency_verifier)
    : cert_verifier_(cert_verifier),
      cert_policy_enforcer_(cert_policy_enforcer),
      transport_security_state_(transport_security_state),
      cert_transparency_verifier_(cert_transparency_verifier) {}

// TODO(kku): Remove this fake constructor.
ProofVerifierOpenSSL::ProofVerifierOpenSSL()
    : cert_verifier_(nullptr),
      cert_policy_enforcer_(nullptr),
      transport_security_state_(nullptr),
      cert_transparency_verifier_(nullptr) {}

ProofVerifierOpenSSL::~ProofVerifierOpenSSL() {
}

QuicAsyncStatus ProofVerifierOpenSSL::VerifyProof(
    const std::string& hostname,
    const std::string& server_config,
    const std::vector<std::string>& certs,
    const std::string& cert_sct,
    const std::string& signature,
    const ProofVerifyContext* verify_context,
    std::string* error_details,
    scoped_ptr<ProofVerifyDetails>* verify_details,
    ProofVerifierCallback* callback) {
  // TODO(kku): Implement
  return QUIC_SUCCESS;
  /*
  if (!verify_context) {
    *error_details = "Missing context";
    return QUIC_FAILURE;
  }
  const ProofVerifyContextChromium* chromium_context =
      reinterpret_cast<const ProofVerifyContextChromium*>(verify_context);
  scoped_ptr<Job> job(
      new Job(this, cert_verifier_, cert_policy_enforcer_,
              transport_security_state_, cert_transparency_verifier_,
              chromium_context->cert_verify_flags, chromium_context->net_log));
  QuicAsyncStatus status =
      job->VerifyProof(hostname, server_config, certs, cert_sct, signature,
                       error_details, verify_details, callback);
  if (status == QUIC_PENDING) {
    active_jobs_.insert(job.release());
  }
  return status;
  */
}

}  // namespace net
