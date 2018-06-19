// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy server, which listens on a specified address for QUIC traffic and
// handles incoming responses.
//
// Note that this server is intended to verify correctness of the client and is
// in no way expected to be performant.

#ifndef _QUICSOCK_SERVER_H_
#define _QUICSOCK_SERVER_H_

#include <stddef.h>

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_framer.h"
#include "net/tools/quic/quic_default_packet_writer.h"

#include "quicsock/quicsock_observer.h"
#include "quicsock/quicsock_event_handler.h"
#include "quicsock/server/quicsock_server_session_base.h"
#include "quicsock/server/quicsock_dispatcher.h"

namespace net {
namespace tools {

namespace test {
class QuicSockServerPeer;
}  // namespace test

class ProcessPacketInterface;
class QuicSockPacketReader;

class QuicSockServer {
 public:
  QuicSockServer(ProofSource* proof_source,
             const QuicConfig& config,
             const QuicVersionVector& supported_versions,
             quicsock::QuicSockObserver* quicsock_observer,
             quicsock::QuicSockEventHandler *event_handler);

  virtual ~QuicSockServer();

  // Bind to the specified address.
  bool Bind(const IPEndPoint& address);

  // Start listening.
  bool Listen();

  // Server deletion is imminent.
  void Shutdown();

  void OnCanRead();
  void OnCanWrite();

  void SetStrikeRegisterNoStartupPeriod() {
    crypto_config_.set_strike_register_no_startup_period();
  }

  void SetChloMultiplier(size_t multiplier) {
    crypto_config_.set_chlo_multiplier(multiplier);
  }

  bool overflow_supported() { return overflow_supported_; }

  QuicPacketCount packets_dropped() { return packets_dropped_; }

  int port() { return port_; }

  QuicSockServerSessionBase* GetSession(QuicConnectionId id) {
    return dispatcher()->GetSession(id);
  }

  int GetFD() {
    return fd_;
  }

 protected:
  virtual QuicDefaultPacketWriter* CreateWriter(int fd);

  virtual QuicSockDispatcher* CreateQuicSockDispatcher();

  const QuicConfig& config() const { return config_; }
  const QuicCryptoServerConfig& crypto_config() const { return crypto_config_; }
  const QuicVersionVector& supported_versions() const {
    return supported_versions_;
  }

  QuicSockDispatcher* dispatcher() { return dispatcher_.get(); }

 private:
  friend class net::tools::test::QuicSockServerPeer;

  // Initialize the internal state of the server.
  void Initialize();

  // Accepts data from the framer and demuxes clients to sessions.
  scoped_ptr<QuicSockDispatcher> dispatcher_;

  // The port the server is listening on.
  int port_;

  // Listening connection.  Also used for outbound client communication.
  int fd_;

  // If overflow_supported_ is true this will be the number of packets dropped
  // during the lifetime of the server.  This may overflow if enough packets
  // are dropped.
  QuicPacketCount packets_dropped_;

  // True if the kernel supports SO_RXQ_OVFL, the number of packets dropped
  // because the socket would otherwise overflow.
  bool overflow_supported_;

  // If true, use recvmmsg for reading.
  bool use_recvmmsg_;

  // config_ contains non-crypto parameters that are negotiated in the crypto
  // handshake.
  QuicConfig config_;
  // crypto_config_ contains crypto parameters for the handshake.
  QuicCryptoServerConfig crypto_config_;

  // This vector contains QUIC versions which we currently support.
  // This should be ordered such that the highest supported version is the first
  // element, with subsequent elements in descending order (versions can be
  // skipped as necessary).
  QuicVersionVector supported_versions_;

  scoped_ptr<QuicSockPacketReader> packet_reader_;

  scoped_ptr<quicsock::QuicSockObserver> quicsock_observer_;

  scoped_ptr<quicsock::QuicSockEventHandler> event_handler_;

  DISALLOW_COPY_AND_ASSIGN(QuicSockServer);
};

}  // namespace tools
}  // namespace net

#endif  // _QUICSOCK_SERVER_H_
