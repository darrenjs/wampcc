#ifndef XXX_WEBSOCKET_PROTOCOL_H
#define XXX_WEBSOCKET_PROTOCOL_H

#include "XXX/protocol.h"

namespace XXX
{


class websocket_protocol : public protocol
{
public:

  struct frame
  {
    bool fin;
    unsigned int opcode;
    unsigned int payload_len;
  };

  static constexpr const unsigned char HEADER_SIZE = 4; /* "GET " */
  static constexpr const char*               MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  static const int OPCODE_CONTINUE = 0x0;
  static const int OPCODE_TEXT     = 0x1;
  static const int OPCODE_BINARY   = 0x2;
  static const int OPCODE_PING     = 0x9;
  static const int OPCODE_PONG     = 0xA;

  static bool is_http_get(const char*, size_t len);

  websocket_protocol(io_handle*, t_msg_cb, connection_mode m);

  int  required_timer_callback_interval_ms() override { return 2000;}
  void ev_on_timer() override;
  void io_on_read(char*, size_t) override;
  void initiate(t_initiate_cb) override;

  void encode(const jalson::json_array& j) override;
private:

  size_t parse_http_handshake(char* const src, size_t const len);
  bool m_get_found;
  bool m_request_crlf_found;
  std::map<std::string, std::string> m_http_headers;


  enum
  {
    eServerHandshakeWait,
    eServerHandshareSent
  } state = eServerHandshakeWait;
};





}

#endif
