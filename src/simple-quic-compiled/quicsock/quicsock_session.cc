// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/quicsock_session.h"

#include <errno.h>
#include <string.h>

#include "net/quic/quic_headers_stream.h"
#include "quicsock/eventfd_util.h"

namespace net {

QuicSockSession::QuicSockSession(QuicConnection* connection,
                                 const QuicConfig& config,
                                 quicsock::QuicSockObserver *quicsock_observer)
    : QuicSession(connection, config),
      eventfd_(-1),
      is_closed_(false),
      peer_left_(false),
      quicsock_observer_(quicsock_observer) {

  if (connection == nullptr)
    return;

  net::QuicConnectionId connID = connection->connection_id();

  // Create eventfd to represent this session.
  eventfd_ = quicsock::CreateEventFD();
  if (eventfd_ < 0) {
    LOG(ERROR) << "Failed to add eventfd for connection " << connID << ": "
        << strerror(errno);
  }

  DVLOG(1) << "Setting eventfd=" << eventfd_ << " for conn=" << connID;

  quicsock_observer_->OnNewSession(connID, this);
}

QuicSockSession::~QuicSockSession() {
  if (!is_closed_)
    CloseSession();

  pthread_mutex_lock(&data_buffer_mutex_);
  if (!data_buffer_.empty()) {
    LOG(WARNING) << "Session for connection " << connection()->connection_id()
        << " destroyed with " <<
        data_buffer_.size() << " unprocessed buffers" << std::endl;
    data_buffer_.clear();
  }
  pthread_mutex_unlock(&data_buffer_mutex_);

  if (pthread_mutex_destroy(&data_buffer_mutex_) != 0) {
    LOG(ERROR) << "Failed to destroy data_buffer_mutex_";
  }
}

void QuicSockSession::Initialize() {
  QuicSession::Initialize();

  CHECK_EQ(pthread_mutex_init(&data_buffer_mutex_, NULL), 0);
}

void QuicSockSession::OnConnectionClosed(QuicErrorCode error, bool from_peer) {
  QuicSession::OnConnectionClosed(error, from_peer);

  peer_left_ = from_peer;

  if (connection() != nullptr) {
    quicsock_observer_->OnConnectionClosed(connection()->connection_id(),
        this, from_peer);
  }

  // Notify eventfd to trigger a read event that will return 0 to indicate
  // the peer has went away.
  quicsock::AddEventToEventFD(eventfd_);
}

void QuicSockSession::CloseSession() {
  if (connection() != nullptr)
    connection()->SendConnectionClose(net::QUIC_PEER_GOING_AWAY);

  // Clear our local outgoing_stream_map_.
  // The actual streams will be closed automatically via the OnConnectionClosed
  // interface, invoked by SendConnectionClose.
  outgoing_stream_map_.clear();

  if (eventfd_ != -1)
    close(eventfd_);

  is_closed_ = true;
}

QuicSockStream* QuicSockSession::GetOrCreateOutgoingStream(
    quicsock_stream_id_t userStreamID) {
  if (connection() == nullptr || !connection()->connected()) {
    LOG(ERROR) << "Cannot create outgoing stream for non-connected connection";
    return nullptr;
  }

  QuicSockStream *stream = nullptr;

  StreamMap::iterator it = outgoing_stream_map_.find(userStreamID);
  if (it == outgoing_stream_map_.end()) {
    // Create new stream.
    stream = static_cast<QuicSockStream*>(CreateOutgoingDynamicStream(0));
    outgoing_stream_map_.insert(std::make_pair(userStreamID, stream));
  } else {
    stream = it->second;
  }

  return stream;
}

void QuicSockSession::RegisterStreamPriority(QuicStreamId id,
    SpdyPriority priority) {
  write_blocked_streams()->RegisterStream(id, priority);
}

void QuicSockSession::UpdateStreamPriority(QuicStreamId id,
                                          SpdyPriority new_priority) {
  write_blocked_streams()->UpdateStreamPriority(id, new_priority);
}

void QuicSockSession::OnDataAvailable(std::string data) {
  pthread_mutex_lock(&data_buffer_mutex_);
  data_buffer_.push_back(data);
  pthread_mutex_unlock(&data_buffer_mutex_);

  DVLOG(1) << "QuicSockSession data available. eventfd=" << eventfd_ << " conn="
       << connection()->connection_id() << " length=" << data.size();

  // Since eventfd has semaphore semantics, we increment the counter by 1 to
  // indicate 1 new data item arrived.
  if (!quicsock::AddEventToEventFD(eventfd_)) {
    LOG(ERROR) << "Failed to notify new data eventfd=" << eventfd_;
    return;
  }
}

ssize_t QuicSockSession::Readv(const struct iovec* iov) {
  size_t bytes_consumed = 0;
  size_t remaining_buf_size = iov->iov_len;

  while (remaining_buf_size > 0) {
    pthread_mutex_lock(&data_buffer_mutex_);
    if (data_buffer_.empty()) {
      pthread_mutex_unlock(&data_buffer_mutex_);
      break;
    }
    std::string data = data_buffer_.front();
    pthread_mutex_unlock(&data_buffer_mutex_);
    // New inserts into data_buffer_ always insert in the back, so we don't have
    // to worry about reordering after we unlock.

    size_t bytes_to_consume = std::min(remaining_buf_size, data.length());

    char* base = (char*) iov->iov_base + bytes_consumed;
    memcpy(base, data.c_str(), bytes_to_consume);
    bytes_consumed += bytes_to_consume;
    remaining_buf_size -= bytes_to_consume;
    
    if (data.length() > bytes_to_consume) {
      CHECK(remaining_buf_size == 0);
      std::string remaining_data = data.substr(bytes_to_consume);
      pthread_mutex_lock(&data_buffer_mutex_);
      data_buffer_.pop_front();
      data_buffer_.push_front(remaining_data);
      pthread_mutex_unlock(&data_buffer_mutex_);
    } else {
      pthread_mutex_lock(&data_buffer_mutex_);
      data_buffer_.pop_front();
      pthread_mutex_unlock(&data_buffer_mutex_);
    }
  }

  CHECK(bytes_consumed <= iov->iov_len);
  return bytes_consumed;
}

int QuicSockSession::GetEventFD() {
  return eventfd_;
}

bool QuicSockSession::PeerLeft() {
  return peer_left_;
}

bool QuicSockSession::HasPendingWrites() {
  QuicConnection * conn = connection();
  return conn != nullptr && (conn->HasQueuedData() ||
      conn->sent_packet_manager().HasPendingRetransmissions());
}

}  // namespace net
