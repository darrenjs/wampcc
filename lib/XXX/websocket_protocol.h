#ifndef XXX_WEBSOCKET_PROTOCOL_H
#define XXX_WEBSOCKET_PROTOCOL_H

#include "XXX/protocol.h"

namespace XXX
{

class http_parser;

class websocket_protocol : public protocol
{
public:

  struct options : public protocol::options
  {
    options(){}
  };
  static constexpr const char* NAME = "websocket";

  static constexpr const unsigned char HEADER_SIZE = 4; /* "GET " */
  static constexpr const char*               MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  static const int OPCODE_CONTINUE = 0x0;
  static const int OPCODE_TEXT     = 0x1;
  static const int OPCODE_BINARY   = 0x2;
  static const int OPCODE_CLOSE    = 0x8;
  static const int OPCODE_PING     = 0x9;
  static const int OPCODE_PONG     = 0xA;

  websocket_protocol(io_handle*, t_msg_cb, connection_mode _mode, options);

  int  required_timer_callback_interval_ms() override { return 2000;}
  void ev_on_timer() override;
  void io_on_read(char*, size_t) override;
  void initiate(t_initiate_cb) override;

  const char* name() const override { return NAME; }
  void send_msg(const jalson::json_array& j) override;

private:

  enum
  {
    eInvalid,
    eHandlingHttpRequest, // server
    eSendingHttpRequest, // client
    eHandlingWebsocket,
    eClosing
  } m_state = eInvalid;

  std::unique_ptr<http_parser> m_http_parser;

  options m_options;
};

}

#endif
