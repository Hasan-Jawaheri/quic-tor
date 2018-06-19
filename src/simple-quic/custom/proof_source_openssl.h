// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku to remove dependency on BoringSSL.

#ifndef NET_QUIC_CRYPTO_PROOF_SOURCE_OPENSLL_H_
#define NET_QUIC_CRYPTO_PROOF_SOURCE_OPENSLL_H_

#include <string>
#include <vector>

#include <openssl/evp.h>

#include "net/quic/crypto/proof_source.h"

namespace net {

// ProofSourceOpenSSL implements the QUIC ProofSource interface.
class ProofSourceOpenSSL : public ProofSource {
 public:
  ProofSourceOpenSSL();
  ~ProofSourceOpenSSL() override;

  // Initializes this object based on the certificate chain in |cert_path|,
  // and the PKCS#8 RSA private key in |key_path|. Signed certificate
  // timestamp may be loaded from |sct_path| if it is non-empty.
  bool Initialize(const std::string& cert_path,
                  const std::string& key_path,
                  const std::string& sct_path);

  // ProofSource interface
  bool GetProof(const IPAddressNumber& server_ip,
                const std::string& hostname,
                const std::string& server_config,
                bool ecdsa_ok,
                const std::vector<std::string>** out_certs,
                std::string* out_signature,
                std::string* out_leaf_cert_sct) override;

 private:
  EVP_PKEY* private_key_;
  // DER-encoded certificates
  std::vector<std::string> certificates_;
  std::string signed_certificate_timestamp_;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_PROOF_SOURCE_CHROMIUM_H_
