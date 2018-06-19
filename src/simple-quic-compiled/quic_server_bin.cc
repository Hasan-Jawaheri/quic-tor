// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#include "server/quic_server.h"

#include <iostream>
#include <string>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "net/base/ip_endpoint.h"
#include "net/base/ip_address_number.h"
#include "net/quic/quic_protocol.h"

#include "custom/proof_source_openssl.h"

// The port the quic server will listen on.
static int32_t FLAGS_port = 6121;

static std::string CERT_FILE = "certs/out/leaf_cert.pem";
static std::string KEY_FILE = "certs/out/leaf_cert.key";

net::ProofSourceOpenSSL* CreateProofSource(const std::string& cert_path,
    const std::string& key_path) {
  net::ProofSourceOpenSSL* proof_source = new net::ProofSourceOpenSSL();
  CHECK(proof_source->Initialize(cert_path, key_path, ""));
  return proof_source;
}

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  base::AtExitManager exit_manager;

  net::IPAddressNumber ip;
  CHECK(net::ParseIPLiteralToNumber("127.0.0.1", &ip));

  net::QuicConfig config;
  net::tools::QuicServer server(CreateProofSource(CERT_FILE, KEY_FILE),
      config, net::QuicSupportedVersions());
  server.SetStrikeRegisterNoStartupPeriod();

  CHECK(server.Bind(net::IPEndPoint(ip, FLAGS_port)));
  CHECK(server.Listen());

  VLOG(1) << "QUIC server started on port " << FLAGS_port;

  while (1) {
    server.WaitForEvents();
  }
}
