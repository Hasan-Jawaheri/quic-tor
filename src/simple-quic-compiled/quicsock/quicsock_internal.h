#ifndef __QUICSOCK_INTERNAL_H__
#define __QUICSOCK_INTERNAL_H__

#include <map>
#include <set>

#include "net/base/ip_endpoint.h"

#include "quicsock/client/quicsock_client.h"
#include "quicsock/quicsock_observer.h"
#include "quicsock/quicsock_session.h"
#include "quicsock/quicsock_types.h"
#include "quicsock/server/quicsock_server.h"
#include "quicsock/socket_event_thread.h"

typedef enum {
  QUICSOCK_UNKNOWN,
  QUICSOCK_SERVER_LISTEN,
  QUICSOCK_SERVER_ACCEPT,
  QUICSOCK_CLIENT
} QuicSockType;

/**
 * @brief Internal representation of quicsock.
 *
 * We use this internal representation to hide C++ types from C code.
 */
struct quicsock_internal_s {
  /** @brief They type of this quicsock. */
  QuicSockType type;

  /**
   * @brief QUIC connection ID that the quicsock socket represents.
   *
   * Because of the design of QUIC on top of UDP, client and server always use
   * the same socket to communicate, with multiple connections multiplexed on
   * the same port. We provide the abstraction of different sockets to the user
   * to make quicsock look like a connection-oriented socket. Each session 
   * is created by QUIC and is uniquely identifiable by its connection ID.
   */
  net::QuicConnectionId connID;

  /** @brief SocketEventThread object. */
  quicsock::SocketEventThread *event_thread;

  /** @brief The address that we should bind to */
  net::IPEndPoint *bind_address;

  /** @Brief The eventfd that will trigger events for this quicsock. */
  int eventfd;
};

#endif  /* __QUICSOCK_INTERNAL_H__ */
