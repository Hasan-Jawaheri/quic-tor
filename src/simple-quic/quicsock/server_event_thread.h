#ifndef __SERVER_EVENT_THREAD__
#define __SERVER_EVENT_THREAD__

#include <pthread.h>
#include <string>

#include "quicsock/socket_event_thread.h"
#include "quicsock/server/quicsock_server.h"

namespace quicsock {

class ServerEventThread : public SocketEventThread {
  public:
    ServerEventThread(std::string& cert_path, std::string& key_path);
    ~ServerEventThread() override;

    bool Initialize() override;

    /**
     * @brief Listen for incoming connections.
     * @param bind_address The address to listen on.
     *
     * This effectively delegates the QuicSock as a server socket.
     *
     * @return true on success, false otherwise.
     */
    bool Listen(net::IPEndPoint *bind_address);

    /**
     * @brief Accept the next incoming connection.
     * @pre The QuicSock is bound and listening.
     * @param connID Pointer to store the QUIC connection ID of the accepted
     *        connection.
     * @param peer Optional struct to store the peer's address.
     * @param arrlen Length of peer.
     *
     * Note that this function does not block.
     *
     * @return eventfd for the session on success, -1 otherwise.
     */
    int Accept(net::QuicConnectionId *connID, struct sockaddr *peer,
        socklen_t *addrlen);

    /**
     * @brief Get the eventfd for accept events.
     * @pre Listen() has been called.
     * @return accept_eventfd_ on success, -1 otherwise.
     */
    int GetAcceptEventFD();

  protected:
    void OnCanReadImpl(int fd) override;
    void OnCanWriteImpl(int fd) override;
    void OnNewSessionImpl(net::QuicConnectionId id,
        net::QuicSockSession* session) override;
    void OnConnectionClosedImpl(net::QuicConnectionId id,
        net::QuicSockSession *session, bool from_peer) override;

  private:
    // Path to PEM-encoded certificate file.
    std::string cert_path_;
    //Path to PEM-encoded private key file.
    std::string key_path_;

    // The server object.
    net::tools::QuicSockServer *server_;

    // eventfd for accept events.
    int accept_eventfd_;

    // Set of "unaccepted" connections from the user's perspective.
    // This is only applicable to server.
    typedef std::set<net::QuicSockSession*> UnacceptedSessionSet;
    UnacceptedSessionSet unaccepted_sessions_;

    // Mutex for unaccetped_sessions_.
    pthread_mutex_t unaccepted_sessions_mutex_;
};

} // namesapce quicsock

#endif /* __SERVER_EVENT_THREAD__ */
