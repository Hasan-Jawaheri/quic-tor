// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/ip_endpoint.h"
#include "net/base/ip_address_number.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/log/net_log.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_server_id.h"
#include "net/quic/quic_utils.h"

#include "custom/message_loop/message_loop.h"
#include "custom/proof_verifier_openssl.h"
#include "client/quic_simple_client.h"

using base::StringPiece;
using net::ProofVerifierOpenSSL;
using std::cout;
using std::cerr;
using std::map;
using std::string;
using std::vector;
using std::endl;

// The host to connect to.
string FLAGS_host = "127.0.0.1";
// The port to connect to.
int32_t FLAGS_port = 6121;
// If set, send a POST with this body.
string FLAGS_body = "Hello World!";
// Set to true for a quieter output experience.
bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);

  //logging::SetMinLogLevel(-2);
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
          << " body: " << FLAGS_body
          << " quiet: " << FLAGS_quiet
          << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " initial_mtu: " << FLAGS_initial_mtu;

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  net::IPAddressNumber ip_addr;

  CHECK(net::ParseIPLiteralToNumber(FLAGS_host, &ip_addr));

  // Build the client, and try to connect.
  net::QuicServerId server_id(FLAGS_host, FLAGS_port,
                              net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::QuicSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(static_cast<net::QuicVersion>(FLAGS_quic_version));
  }

  /*
  // For secure QUIC we need to verify the cert chain.
  scoped_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  if (line->HasSwitch("disable-certificate-verification")) {
    cert_verifier.reset(new FakeCertVerifier());
  }
  scoped_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  scoped_ptr<CTVerifier> ct_verifier(new MultiLogCTVerifier());
  ProofVerifierChromium* proof_verifier = new ProofVerifierChromium(
      cert_verifier.get(), nullptr, transport_security_state.get(),
      ct_verifier.get());
  */
  ProofVerifierOpenSSL* proof_verifier = new ProofVerifierOpenSSL();

  net::tools::QuicSimpleClient client(net::IPEndPoint(ip_addr, FLAGS_port), server_id,
                                      versions, proof_verifier);
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize);
  if (!client.Initialize()) {
    DLOG(FATAL) << "Failed to initialize client." << endl;
    return 1;
  }

  if (!client.Connect()) {
    net::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
      DLOG(ERROR) << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << QuicVersionVectorToString(versions) << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    DLOG(FATAL) << "Failed to connect to " << FLAGS_port
         << ". Error: " << net::QuicUtils::ErrorToString(error) << endl;
    return 1;
  }
  VLOG(1) << "Connected to " << FLAGS_port << endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;

  // Make sure to store the response, for later output.
  client.set_store_response(true);

  // Send the request.
  VLOG(1) << "Going to send request and wait for response";
  client.SendRequestAndWaitForResponse(body, /*fin=*/true);

  // Print request and response details.
  if (!FLAGS_quiet) {
    cout << "Request:" << endl;
    cout << "body: " << body << endl;
    cout << endl;
    cout << "Response:" << endl;
    string response_body = client.latest_response_body();
    cout << "body: " << response_body << endl;
  }
}
