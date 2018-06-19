// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku to remove dependency on BoringSSL.
//
// References:
// https://www.openssl.org/docs/manmaster/crypto/pem.html
// https://www.openssl.org/docs/manmaster/crypto/d2i_X509.html (for DER-encoded certs)
// http://stackoverflow.com/questions/17400058/how-to-use-openssl-lib-pem-read-to-read-public-private-key-from-a-string
// http://stackoverflow.com/questions/17852325/how-to-convert-the-x509-structure-into-string

#include "proof_source_openssl.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h> 
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "base/logging.h"
#include "net/quic/crypto/crypto_protocol.h"

#include "file_util.h"

using std::string;
using std::vector;

namespace net {

ProofSourceOpenSSL::ProofSourceOpenSSL() {
  private_key_ = EVP_PKEY_new();
}

ProofSourceOpenSSL::~ProofSourceOpenSSL() {
  EVP_PKEY_free(private_key_);
}

void InitializeSSL() {
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

void DestroySSL() {
  ERR_free_strings();
  EVP_cleanup();
}

// cert_path: path to PEM-encoded certificate
// key_path: path to PEM-encoded private key
// sct_path: signed certificate timestamp file (optional)
bool ProofSourceOpenSSL::Initialize(const std::string& cert_path,
                                     const std::string& key_path,
                                     const std::string& sct_path) {
  // Initialize OpenSSL.
  InitializeSSL();

  // Parse PEM-encoded x509 certificate.
  FILE *cert_file = OpenFile(cert_path, "rb");
  BIO *cert_bio = BIO_new_fp(cert_file, BIO_NOCLOSE);
  X509 *cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);
  CloseFile(cert_file);

  if (cert == NULL) {
    DLOG(FATAL) << "Cannot read certifcate from file " << cert_path;
    return false;
  }

  // Re-encode certificate to DER
  // Re-encoding the DER data via i2d_X509 is an expensive operation,
  // but it's necessary for comparing two certificates.
  // See net/cert/x509_util_openssl.cc
  BIO *b64 = BIO_new(BIO_s_mem());
  if (i2d_X509_bio(b64, cert) != 1) {
    DLOG(FATAL) << "Failed to re-encode certificate to DER";
    BIO_free(b64);
    return false;
  }
  BUF_MEM *bptr;
  BIO_get_mem_ptr(b64, &bptr);
  std::string cert_buf(bptr->data, bptr->length);
  certificates_.push_back(cert_buf);
  BIO_free(b64);

  // Read PEM-encoded private key.
  FILE *key_file = OpenFile(key_path, "rb");
  BIO *key_bio = BIO_new_fp(key_file, BIO_NOCLOSE);
  PEM_read_bio_PrivateKey(key_bio, &private_key_, 0, 0);
  BIO_free(key_bio);
  CloseFile(key_file);

  // Loading of the signed certificate timestamp is optional.
  if (sct_path.empty())
    return true;

  if (!ReadFileToString(sct_path, &signed_certificate_timestamp_)) {
    DLOG(FATAL) << "Unable to read signed certificate timestamp.";
    return false;
  }

  return true;
}

bool ProofSourceOpenSSL::GetProof(const IPAddressNumber& server_ip,
                                   const string& hostname,
                                   const string& server_config,
                                   bool ecdsa_ok,
                                   const vector<string>** out_certs,
                                   string* out_signature,
                                   string* out_leaf_cert_sct) {
  DCHECK(private_key_) << " this: " << this;

  EVP_MD_CTX *sign_context = EVP_MD_CTX_create();
  EVP_PKEY_CTX *pkey_ctx;
  // Note: EVP_PKEY_CTX_set_rsa_pss_saltlen in openssl/rsa.h will call
  // EVP_PKEY_CTX_ctrl with the 5th argument being NULL.
  // If we use boringSSL implementation of EVP_PKEY_CTX_ctrl, this will cause a
  // segfault on line 375 in boringssl/crypto/evp/p_rsa.c.
  if (!EVP_DigestSignInit(sign_context, &pkey_ctx, EVP_sha256(), nullptr,
                          private_key_) ||
      !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) ||
      !EVP_DigestSignUpdate(
          sign_context,
          // kProofSignatureLabel is defined in net/quic/crypto/crypto_protocol.h
          reinterpret_cast<const uint8_t*>(kProofSignatureLabel),
          sizeof(kProofSignatureLabel)) ||
      !EVP_DigestSignUpdate(
          sign_context,
          reinterpret_cast<const uint8_t*>(server_config.data()),
          server_config.size())) {
    EVP_MD_CTX_destroy(sign_context);
    return false;
  }

  // Determine the maximum length of the signature.
  size_t len = 0;
  if (!EVP_DigestSignFinal(sign_context, nullptr, &len)) {
    EVP_MD_CTX_destroy(sign_context);
    return false;
  }
  std::vector<uint8_t> signature(len);
  // Sign it.
  if (!EVP_DigestSignFinal(sign_context, signature.data(), &len)) {
    EVP_MD_CTX_destroy(sign_context);
    return false;
  }
  signature.resize(len);
  out_signature->assign(reinterpret_cast<const char*>(signature.data()),
                        signature.size());
  *out_certs = &certificates_;
  *out_leaf_cert_sct = signed_certificate_timestamp_;

  EVP_MD_CTX_destroy(sign_context);

  return true;
}

}  // namespace net
