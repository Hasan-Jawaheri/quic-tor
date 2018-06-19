// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUICSOCK_CONNECTION_HELPER_H_
#define NET_QUIC_QUICSOCK_CONNECTION_HELPER_H_

#include "net/quic/quic_connection.h"

#include <set>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_simple_buffer_allocator.h"
#include "net/quic/quic_time.h"

#include "quicsock/quicsock_alarm.h"
#include "quicsock/quicsock_event_handler.h"

namespace net {

class QuicClock;
class QuicRandom;

class NET_EXPORT_PRIVATE QuicSockConnectionHelper
    : public QuicConnectionHelperInterface {
 public:
  QuicSockConnectionHelper(const QuicClock* clock,
      QuicRandom* random_generator,
      quicsock::QuicSockEventHandler *event_handler);
  ~QuicSockConnectionHelper() override;

  // QuicSockConnectionHelperInterface
  const QuicClock* GetClock() const override;
  QuicRandom* GetRandomGenerator() override;
  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;
  QuicBufferAllocator* GetBufferAllocator() override;

 private:
  const QuicClock* clock_;
  QuicRandom* random_generator_;

  quicsock::QuicSockEventHandler *event_handler_;

  SimpleBufferAllocator buffer_allocator_;
  base::WeakPtrFactory<QuicSockConnectionHelper> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicSockConnectionHelper);
};

}  // namespace net

#endif  // NET_QUIC_QUICSOCK_CONNECTION_HELPER_H_
