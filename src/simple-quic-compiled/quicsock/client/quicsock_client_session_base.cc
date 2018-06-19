// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quicsock/client/quicsock_client_session_base.h"

#include "net/quic/quic_flags.h"

namespace net {

QuicSockClientSessionBase::QuicSockClientSessionBase(QuicConnection* connection,
    const QuicConfig& config, quicsock::QuicSockObserver *quicsock_observer)
    : QuicSockSession(connection, config, quicsock_observer) {}

QuicSockClientSessionBase::~QuicSockClientSessionBase() {}

}  // namespace net
