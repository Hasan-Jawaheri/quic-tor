// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The base class for streams which deliver data to/from an application.
//
// Modified by kku to remove spdy

#ifndef NET_QUIC_QUICSOCK_STREAM_H_
#define NET_QUIC_QUICSOCK_STREAM_H_

#include <stddef.h>
#include <sys/types.h>

#include <list>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/iovec.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_stream_sequencer.h"
#include "net/quic/reliable_quic_stream.h"

namespace net {

class QuicSockSession;

// From quic_spdy_stream.h
// This is somewhat arbitrary.  It's possible, but unlikely, we will either fail
// to set a priority client-side, or cancel a stream before stripping the
// priority from the wire server-side.  In either case, start out with a
// priority in the middle.
const SpdyPriority kDefaultPriority = 3;

class NET_EXPORT_PRIVATE QuicSockStream : public ReliableQuicStream {
 public:
  // Visitor receives callbacks from the stream.
  class NET_EXPORT_PRIVATE Visitor {
   public:
    Visitor() {}

    // Called when the stream is closed.
    virtual void OnClose(QuicSockStream* stream) = 0;

   protected:
    virtual ~Visitor() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Visitor);
  };

  QuicSockStream(QuicStreamId id, QuicSockSession* session);
  ~QuicSockStream() override;

  // Called when data is available to be read.
  // Called when new data is available from the sequencer. Subclasses of
  // ReliableQuicStream must actively retrieve the data using the sequencer's
  // Readv() or GetReadableRegions() method.
  virtual void OnDataAvailable() override;

  // ReliableQuicStream
  void OnClose() override;

  // This is the same as priority() and is being deprecated
  // TODO(alyssar) remove after Priority refactor.
  SpdyPriority Priority() const override;

  bool IsDoneReading() const;
  bool HasBytesToRead() const;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

  // This is the same as Priority.
  SpdyPriority priority() const { return priority_; }

  // Sets priority_ to priority.  This should only be called before bytes are
  // written to the server.
  void SetPriority(SpdyPriority priority);

  // Custom read/write functions.
  virtual ssize_t Writev(void *buf, size_t len, bool is_fin);
  virtual ssize_t Readv(const struct iovec* iov);

 private:
  friend class QuicStreamUtils;

  QuicSockSession* quicsock_session_;

  // The priority of the stream, once parsed.
  SpdyPriority priority_;

  Visitor* visitor_;

  DISALLOW_COPY_AND_ASSIGN(QuicSockStream);
};

}  // namespace net

#endif  // NET_QUIC_QUICSOCK_STREAM_H_
