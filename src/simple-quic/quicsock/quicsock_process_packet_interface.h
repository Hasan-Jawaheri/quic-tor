#ifndef _QUICSOCK_PROCESS_PACKET_INTERFACE_H_
#define _QUICSOCK_PROCESS_PACKET_INTERFACE_H_

namespace net {
namespace tools {

class ProcessPacketInterface {
 public:
  virtual ~ProcessPacketInterface() {}
  virtual void ProcessPacket(const IPEndPoint& server_address,
                             const IPEndPoint& client_address,
                             const QuicEncryptedPacket& packet) = 0;
};

} // namespace tools
} // namespace net

#endif /* _QUICSOCK_PROCESS_PACKET_INTERFACE_H_ */
