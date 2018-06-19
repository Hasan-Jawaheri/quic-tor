#ifndef __QUICSOCK_H__
#define __QUICSOCK_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "quicsock/quicsock_types.h"

#define INVALID_QUICSOCK NULL

#ifdef __cplusplus
  extern "C" {
#endif
  /**
   * @brief Initializes the quicsock module.
   * @param cert_path Path to PEM-encoded certificate file.
   * @param key_path Path to PEM-encoded private key file.
   */
  void qs_init(const char *cert_path, const char *key_path);

  /**
   * @brief Creates a new quicsock_t.
   * @return The new socket on success. INVALID_QUICSOCK otherwise.
   */
  quicsock_t qs_open();

  /**
   * @brief Closes the given socket.
   */
  void qs_close(quicsock_t sock);

  // Server
  /**
   * @brief Binds the given address to the given socket>
   * @pre sock is not bound or connected.
   * @param sock The socket.
   * @param addr sockaddr struct representing the address to bind to.
   * @param addrlen Size of addr, in bytes.
   * @return 0 on success, -1 otherwise.
   */
  int qs_bind(quicsock_t sock, const struct sockaddr *addr, socklen_t addrlen);

  /**
   * @brief Listen for connections.
   * @pre sock is bound to an address.
   * @param sock The socket to listen.
   * @return 0 on success, -1 otherwise.
   */
  int qs_listen(quicsock_t sock);

  /**
   * @brief Accept a connection on the given socket.
   * @pre sock is listening.
   * @param sock The listening socket.
   * @param peer Struct to store the peer address of the accepted connection.
   * @param addrlen On input, this should be the size of peer. On output, it
   *                will contain the actual size of the address returned.
   * @return A new quicsock that connects to the client. INVALID_QUICSOCK if
   *    there are no pending connections.
   */
  quicsock_t qs_accept(quicsock_t qs, struct sockaddr *peer,
      socklen_t *addrlen);

  // Client
  /**
   * @brief Connect to the destination.
   * @pre sock is not bound or connected.
   * @param sock The socket to use.
   * @param dst_addr sockaddr struct representing the destination.
   * @param addrlen Size of dst_addr, in bytes.
   * @return 0 on success, -1 otherwise.
   */
  int qs_connect(quicsock_t sock, const struct sockaddr *dst_addr,
      socklen_t addrlen);

  /**
   * @brief Send the given buffer. The function does not block.
   * @pre sock is connected.
   * @param sock Socket to use.
   * @param buf Buffer to containing the data.
   * @param len Size of the buffer.
   * @param user_stream_id User defined identifier for the stream to use.
   * @return number of bytes sent on success, -1 otherwise.
   */
  ssize_t qs_send(quicsock_t sock, void *buf, size_t len,
      quicsock_stream_id_t user_stream_id);

  /**
   * @brief Read up to len bytes to the given buffer.
   * @pre sock is connected.
   * @param sock Socket to use.
   * @param buf Buffer to containing the data.
   * @param len Size of the buffer.
   * @return number of bytes received on success, 0 if the peer has went away,
   *         and -1 on error, -2 if there is no data to be read (but peer has
   *         not left).
   */
  ssize_t qs_recv(quicsock_t sock, void *buf, size_t len);

  /**
   * @brief Get the ID of the given socket.
   * @param qs The quicsock of interest.
   * @return The socket ID.
   */
  uint64_t qs_get_id(quicsock_t qs);

  /**
   * @brief Returns the underlying socket file descriptor. DO NOT manipulate it
   *        directly! Use with an event-driven framework like libevent to
   *        monitor events.
   * @param qs The quicsock to get file descriptor from.
   * @return The socket file descriptor on success, -1 otherwise.
   */
  int qs_get_fd(quicsock_t qs);
#ifdef __cplusplus
  }
#endif

#endif  /* __QUICSOCK_H__ */
