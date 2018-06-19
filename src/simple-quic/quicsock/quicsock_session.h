// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Modified by kku

#ifndef NET_QUIC_QUICSOCK_SESSION_H_
#define NET_QUIC_QUICSOCK_SESSION_H_

#include <map>
#include <pthread.h>
#include <stddef.h>
#include <string>

#include "base/macros.h"
#include "net/base/iovec.h"
#include "net/quic/quic_session.h"

#include "quicsock/quicsock_types.h"
#include "quicsock/quicsock_stream.h"
#include "quicsock/quicsock_observer.h"

namespace net {

// A QUIC session with a headers stream.
class NET_EXPORT_PRIVATE QuicSockSession : public QuicSession {
 public:
  QuicSockSession(QuicConnection* connection, const QuicConfig& config,
      quicsock::QuicSockObserver *quicsock_observer);

  ~QuicSockSession() override;

  void Initialize() override;

  void OnConnectionClosed(QuicErrorCode error, bool from_peer) override;

  void CloseSession();

  void RegisterStreamPriority(QuicStreamId id, SpdyPriority priority);

  // Called by the stream on SetPriority to update priority on the write blocked
  // list.
  void UpdateStreamPriority(QuicStreamId id, SpdyPriority new_priority);

  QuicSockStream* GetOrCreateOutgoingStream(quicsock_stream_id_t userStreamID);

  // Called by the stream to notify of new data.
  void OnDataAvailable(std::string data);

  // Custom read/write functions.
  virtual ssize_t Readv(const struct iovec* iov);

  int GetEventFD();

  bool PeerLeft();

  // Returns whether the underlying connection has pending writes to make.
  bool HasPendingWrites();

 protected:
  // Override CreateIncomingDynamicStream() and CreateOutgoingDynamicStream()
  // with QuicSockStream return type to make sure that all data streams are
  // QuicSockStreams.
  QuicSockStream* CreateIncomingDynamicStream(QuicStreamId id) override = 0;
  QuicSockStream* CreateOutgoingDynamicStream(SpdyPriority priority) override =
      0;

 private:
  // Buffer of data received.
  list<std::string> data_buffer_;

  // Mutex for data_buffer_. Need syncrhonization because socket event thread
  // will insert into it while user may call read to retrieve data.
  pthread_mutex_t data_buffer_mutex_;

  // Map user specified stream id to actual stream.
  typedef std::map<quicsock_stream_id_t, QuicSockStream*> StreamMap;
  StreamMap outgoing_stream_map_;

  // eventfd used to notify user of new data.
  // Owned by the session.
  int eventfd_;

  bool is_closed_;

  bool peer_left_;

  quicsock::QuicSockObserver *quicsock_observer_;
  
  DISALLOW_COPY_AND_ASSIGN(QuicSockSession);
};

}  // namespace net

#endif  // NET_QUIC_QUICSOCK_SESSION_H_
