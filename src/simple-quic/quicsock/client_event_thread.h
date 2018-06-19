#ifndef __CLIENT_EVENT_THREAD__
#define __CLIENT_EVENT_THREAD__

#include <string>

#include "quicsock/client/quicsock_client.h"
#include "quicsock/quicsock_session.h"
#include "quicsock/socket_event_thread.h"

namespace quicsock {

class ClientEventThread : public SocketEventThread {
  public:
    ClientEventThread();
    ~ClientEventThread() override;

    /**
     * @brief Connect to the destination address.
     * @pre The QuicSock is not bound.
     * @param dst_addr The destination address.
     * @param connID Pointer to store the QUIC connection ID.
     *
     * This function effectively delegates the QuicSock as a client socket.
     *
     * @return The eventfd for the session on success, negative number
     *         otherwise.
     */
    int Connect(net::IPEndPoint& dst_addr, net::QuicConnectionId *connID);

  protected:
    void OnCanReadImpl(int fd) override;
    void OnCanWriteImpl(int fd) override;
    void OnNewSessionImpl(net::QuicConnectionId id,
        net::QuicSockSession* session) override;
    void OnConnectionClosedImpl(net::QuicConnectionId id,
        net::QuicSockSession *session, bool from_peer) override;

  private:
    // The server object.
    net::tools::QuicSockClient *client_;

    // A client can only have 1 session.
    net::QuicSockSession *session_;
};

} // namesapce quicsock

#endif /* __CLIENT_EVENT_THREAD__ */
