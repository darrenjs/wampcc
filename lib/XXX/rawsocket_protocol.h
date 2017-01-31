#ifndef XXX_RAWSOCKET_PROTOCOL_H
#define XXX_RAWSOCKET_PROTOCOL_H

#include "XXX/protocol.h"

namespace XXX {

class rawsocket_protocol : public protocol
{
public:

  /** Enumeration used to specify the maximum length of messages that a raw
      socket transport can receive. */
  enum max_msg_size_flag
  {
    e_512_b = 0,
    e_1_kb,
    e_2_kb,
    e_4_kb,
    e_8_kb,
    e_16_kb,
    e_32_kb,
    e_64_kb,
    e_128_kb,
    e_256_kb,
    e_512_kb,
    e_1_mb,
    e_2_mb,
    e_4_mb,
    e_8_mb,
    e_16_mb
  };

  /** The default maximum length for received (RX) messages. */
  static constexpr max_msg_size_flag default_max_rxmsg_size = rawsocket_protocol::e_16_mb;

  enum serialiser_flag
  {
    e_INVALID = 0,
    e_JSON    = 1,
    e_MSGPACK = 2
  };

  struct options : public protocol::options
  {
    max_msg_size_flag inbound_max_msg_size;
    options()
      : inbound_max_msg_size(rawsocket_protocol::default_max_rxmsg_size)
    {}

    options(max_msg_size_flag __inbound_max_msg_size)
      : inbound_max_msg_size(__inbound_max_msg_size)
    {}
  };

  static constexpr const char* NAME = "rawsocket";

  static constexpr int           HANDSHAKE_SIZE = 4;
  static constexpr int           FRAME_PREFIX_SIZE = 4;
  static constexpr unsigned char MAGIC = 0x7F;

  rawsocket_protocol(tcp_socket*, t_msg_cb, protocol::protocol_callbacks callbacks, connection_mode, options);

  void on_timer() override;
  void io_on_read(char*, size_t) override;
  void initiate(t_initiate_cb) override;
  const char* name() const override { return NAME; }
  void send_msg(const jalson::json_array& j);

private:
  static const int FRAME_MSG_LEN_MASK       = 0x00FFFFFF;
  static const int FRAME_RESERVED_MASK      = 0xF8000000;
  static const int FRAME_MSG_TYPE_MASK      = 0x07000000;
  static const int FRAME_FIRST_OCTECT_SHIFT = 24;

  static const int MSG_TYPE_WAMP = 0;
  static const int MSG_TYPE_PING = 1;
  static const int MSG_TYPE_PONG = 2;

  void decode(const char*, size_t);

  enum handshake_error_code
  {
    e_SerialiserUnsupported    = 1,
    e_MaxMsgLengthUnacceptable = 2,
    e_UseOfReservedBits        = 3,
    e_MaxConnectionCountReach  = 4
  };

  static const char* handshake_error_code_to_sting(handshake_error_code);

  void reply_handshake(int, int);

  enum Status
  {
    eHandshaking = 0,
    eOpen,
    eClosing,
    eClosed
  } m_state = eHandshaking;

  t_initiate_cb m_initiate_cb;

  options m_options;

  /* maximum messages that this-side and remote-side can accept */
  unsigned int m_self_max_msg_size;
  unsigned int m_peer_max_msg_size;

  /* time when previous pong was sent */
  std::chrono::system_clock::time_point m_last_pong;
};



}

#endif
