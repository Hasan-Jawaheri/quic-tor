// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy client, which connects to a specified port and sends QUIC
// request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUICSOCK_CLIENT_H_
#define NET_TOOLS_QUIC_QUICSOCK_CLIENT_H_

#include <stddef.h>

#include <string>

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_config.h"

#include "quicsock/client/quicsock_client_base.h"
#include "quicsock/quicsock_event_handler.h"
#include "quicsock/quicsock_observer.h"
#include "quicsock/quicsock_stream.h"

namespace net {

class QuicServerId;

namespace tools {

class QuicEpollConnectionHelper;

class QuicSockClient : public QuicSockClientBase,
                       public quicsock::QuicSockEventHandler::SocketCallback,
                       public QuicSockStream::Visitor {
 public:
  // The client uses these objects to keep track of any data to resend upon
  // receipt of a stateless reject.  Recall that the client API allows callers
  // to optimistically send data to the server prior to handshake-confirmation.
  // If the client subsequently receives a stateless reject, it must tear down
  // its existing session, create a new session, and resend all previously sent
  // data.  It uses these objects to keep track of all the sent data, and to
  // resend the data upon a subsequent connection.
  class QuicDataToResend {
   public:
    QuicDataToResend(base::StringPiece body, bool fin);

    virtual ~QuicDataToResend();

    // Must be overridden by specific classes with the actual method for
    // re-sending data.
    virtual void Resend() = 0;

   protected:
    base::StringPiece body_;
    bool fin_;

   private:
    DISALLOW_COPY_AND_ASSIGN(QuicDataToResend);
  };

  // Create a quic client, which will have events managed by an externally owned
  // EpollServer.
  QuicSockClient(IPEndPoint server_address,
                const QuicServerId& server_id,
                const QuicVersionVector& supported_versions,
                quicsock::QuicSockEventHandler *event_handler,
                ProofVerifier* proof_verifier,
                quicsock::QuicSockObserver *quicsock_observer);
  QuicSockClient(IPEndPoint server_address,
                const QuicServerId& server_id,
                const QuicVersionVector& supported_versions,
                const QuicConfig& config,
                quicsock::QuicSockEventHandler *event_handler,
                ProofVerifier* proof_verifier,
                quicsock::QuicSockObserver *quicsock_observer);

  ~QuicSockClient() override;

  // From QuicSockClientBase
  bool Initialize() override;
  bool WaitForEvents() override;

  // "Connect" to the QUIC server, including performing synchronous crypto
  // handshake.
  bool Connect();

  // Start the crypto handshake.  This can be done in place of the synchronous
  // Connect(), but callers are responsible for making sure the crypto handshake
  // completes.
  void StartConnect();

  // Disconnects from the QUIC server.
  void Disconnect();

  // Sends a request and does not wait for response before returning.
  void SendRequest(base::StringPiece body,
                   bool fin);

  // Migrate to a new socket during an active connection.
  bool MigrateSocket(const IPAddressNumber& new_host);

  // QuicSockStream::Visitor
  void OnClose(QuicSockStream* stream) override;

  // If the crypto handshake has not yet been confirmed, adds the data to the
  // queue of data to resend if the client receives a stateless reject.
  // Otherwise, deletes the data.  Takes ownerership of |data_to_resend|.
  void MaybeAddQuicDataToResend(QuicDataToResend* data_to_resend);

  void set_bind_to_address(IPAddressNumber address) {
    bind_to_address_ = address;
  }

  IPAddressNumber bind_to_address() const { return bind_to_address_; }

  void set_local_port(int local_port) { local_port_ = local_port; }

  const IPEndPoint& server_address() const { return server_address_; }

  const IPEndPoint& client_address() const { return client_address_; }

  int fd() { return fd_; }

  int GetFD() { return fd_; }

  // QuicSockEventHandler::SocketCallback.
  void OnCanRead(int fd);
  void OnCanWrite(int fd);

 protected:
  virtual QuicPacketWriter* CreateQuicPacketWriter();

  virtual int ReadPacket(char* buffer,
                         int buffer_len,
                         IPEndPoint* server_address,
                         IPAddressNumber* client_ip);

  // If the socket has been created, then unregister and close() the FD.
  virtual void CleanUpUDPSocket();

 private:
  // Specific QuicSockClient class for storing data to resend.
  class ClientQuicDataToResend : public QuicDataToResend {
   public:
    // Takes ownership of |headers|.
    ClientQuicDataToResend(base::StringPiece body,
                           bool fin,
                           QuicSockClient* client)
        : QuicDataToResend(body, fin), client_(client) {
      DCHECK(client);
    }

    ~ClientQuicDataToResend() override {}

    void Resend() override;

   private:
    QuicSockClient* client_;

    DISALLOW_COPY_AND_ASSIGN(ClientQuicDataToResend);
  };

  // Used during initialization: creates the UDP socket FD, sets socket options,
  // and binds the socket to our address.
  bool CreateUDPSocket();

  // Actually clean up the socket.
  void CleanUpUDPSocketImpl();

  // Read a UDP packet and hand it to the framer.
  bool ReadAndProcessPacket();

  // Address of the server.
  const IPEndPoint server_address_;

  // Address of the client if the client is connected to the server.
  IPEndPoint client_address_;

  // If initialized, the address to bind to.
  IPAddressNumber bind_to_address_;
  // Local port to bind to. Initialize to 0.
  int local_port_;

  // UDP socket.
  int fd_;

  // Tracks if the client is initialized to connect.
  bool initialized_;

  // If overflow_supported_ is true, this will be the number of packets dropped
  // during the lifetime of the server.
  QuicPacketCount packets_dropped_;

  // True if the kernel supports SO_RXQ_OVFL, the number of packets dropped
  // because the socket would otherwise overflow.
  bool overflow_supported_;

  // Keeps track of any data sent before the handshake.
  std::vector<QuicDataToResend*> data_sent_before_handshake_;

  // Once the client receives a stateless reject, keeps track of any data that
  // must be resent upon a subsequent successful connection.
  std::vector<QuicDataToResend*> data_to_resend_on_connect_;

  // Event handler used to handle UDP events during connect. Not owned by us.
  quicsock::QuicSockEventHandler *event_handler_;

  DISALLOW_COPY_AND_ASSIGN(QuicSockClient);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUICSOCK_CLIENT_H_
