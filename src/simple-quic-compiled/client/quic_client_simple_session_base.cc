// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic_client_simple_session_base.h"

#include "net/quic/quic_flags.h"

namespace net {

QuicClientSimpleSessionBase::QuicClientSimpleSessionBase(QuicConnection* connection,
                                             const QuicConfig& config)
    : QuicSimpleSession(connection, config) {}

QuicClientSimpleSessionBase::~QuicClientSimpleSessionBase() {}

}  // namespace net
