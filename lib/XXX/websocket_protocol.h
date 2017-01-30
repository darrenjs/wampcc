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

  static constexpr const int    HEADER_SIZE = 4; /* "GET " */
  static constexpr const char*  MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  static const int OPCODE_CONTINUE = 0x0;
  static const int OPCODE_TEXT     = 0x1;
  static const int OPCODE_BINARY   = 0x2;
  static const int OPCODE_CLOSE    = 0x8;
  static const int OPCODE_PING     = 0x9;
  static const int OPCODE_PONG     = 0xA;

  websocket_protocol(tcp_socket*, t_msg_cb, protocol::protocol_callbacks, connection_mode _mode, options);

  void on_timer() override;
  void io_on_read(char*, size_t) override;
  void initiate(t_initiate_cb) override;

  const char* name() const override { return NAME; }
  void send_msg(const jalson::json_array& j) override;

private:

  enum
  {
    eInvalid,
    eHandlingHttpRequest, // server
    eHandlingHttpResponse,  // client
    eOpen,
    eClosing
  } m_state = eInvalid;

  t_initiate_cb m_initiate_cb;

  std::unique_ptr<http_parser> m_http_parser;

  options m_options;

  std::string m_expected_accept_key;
};

}

#endif
