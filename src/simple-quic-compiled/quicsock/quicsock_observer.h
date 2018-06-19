#ifndef _QUICSOCK_OBSERVER_H_
#define _QUICSOCK_OBSERVER_H_

#include "net/quic/quic_protocol.h"

namespace net {
class QuicSockSession;
} // namespace net

namespace quicsock {

// Event hooks for QuicSock.
class QuicSockObserver {
  public:
    // Every connection is owned by a session, so we can uniquely identify a
    // session from the connection ID.
    virtual void OnNewSession(net::QuicConnectionId id,
        net::QuicSockSession* session) = 0;
    virtual void OnConnectionClosed(net::QuicConnectionId id,
        net::QuicSockSession* session, bool from_peer) = 0;
};

} // namespace quicsock

#endif /* _QUICSOCK_OBSERVER_H_ */
