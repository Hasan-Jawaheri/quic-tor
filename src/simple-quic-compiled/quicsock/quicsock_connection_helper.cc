// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/quicsock_connection_helper.h"

#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/sparse_histogram.h"
#include "base/task_runner.h"
#include "base/time/time.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/quic/quic_utils.h"

namespace net {

QuicSockConnectionHelper::QuicSockConnectionHelper(const QuicClock* clock,
    QuicRandom* random_generator,
    quicsock::QuicSockEventHandler *event_handler)
    : clock_(clock),
      random_generator_(random_generator),
      event_handler_(event_handler),
      weak_factory_(this) {}

QuicSockConnectionHelper::~QuicSockConnectionHelper() {}

const QuicClock* QuicSockConnectionHelper::GetClock() const {
  return clock_;
}

QuicRandom* QuicSockConnectionHelper::GetRandomGenerator() {
  return random_generator_;
}

QuicAlarm* QuicSockConnectionHelper::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new quicsock::QuicSockAlarm(clock_, delegate, event_handler_);
}

QuicBufferAllocator* QuicSockConnectionHelper::GetBufferAllocator() {
  return &buffer_allocator_;
}

}  // namespace net
