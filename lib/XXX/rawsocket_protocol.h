#ifndef XXX_RAWSOCKET_PROTOCOL_H
#define XXX_RAWSOCKET_PROTOCOL_H

#include "XXX/protocol.h"

namespace XXX {

class rawsocket_protocol : public protocol
{
public:
  static constexpr unsigned char HEADER_SIZE = 4;
  static constexpr unsigned char SERIALIZER_JSON = 1;
  static constexpr unsigned char SERIALIZER_MSGPACK = 2;
  static constexpr unsigned char MAGIC = 0x7F;
  static constexpr unsigned int  MASK_SERIALIZER = 0x0F;
  static constexpr unsigned int  MASK_MAX_LENGTH = 0xF0;

  rawsocket_protocol(io_handle*, t_msg_cb, connection_mode m);

  void io_on_read(char*, size_t) override;
   void initiate(t_initiate_cb) override;

private:

  void decode(const char*, size_t);

  enum Status
  {
    ePendingHandshake = 0,
    eHandshakeComplete
  } m_state = ePendingHandshake;

  t_initiate_cb m_initiate_cb;
};



}

#endif
