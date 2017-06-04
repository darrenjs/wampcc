/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_WEBSOCKET_PROTOCOL_H
#define WAMPCC_WEBSOCKET_PROTOCOL_H

#include "wampcc/protocol.h"

#include <random>

namespace wampcc
{

class http_parser;
class websocketpp_impl;
class websocketpp_msg;

class websocket_protocol : public protocol
{
public:

  struct options : public protocol::options { };

  static constexpr const char* NAME = "websocket";

  static constexpr const int    HEADER_SIZE = 4; /* "GET " */
  static constexpr const char*  MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  static constexpr const char* WAMPV2_JSON_SUBPROTOCOL = "wamp.2.json";
  static constexpr const char* WAMPV2_MSGPACK_SUBPROTOCOL = "wamp.2.msgpack";

  static constexpr const char* RFC6455 = "13";

  websocket_protocol(kernel*, tcp_socket*, t_msg_cb, protocol::protocol_callbacks, connect_mode _mode, options);

  void on_timer() override;
  void io_on_read(char*, size_t) override;
  void initiate(t_initiate_cb) override;

  const char* name() const override { return NAME; }
  void send_msg(const json_array& j) override;

private:

  void process_frame_bytes(buffer::read_pointer&);

  const std::string& header_field(const char*) const;

  static serialiser_type to_serialiser(const std::string&);
  static const char* to_header(serialiser_type);
  static int to_opcode(serialiser_type);

  void send_ping();
  void send_pong();
  void send_close(uint16_t, const std::string&);
  void send_impl(const websocketpp_msg&);

  enum class state
  {
    invalid,
    handling_http_request, // server
    handling_http_response,  // client
    open,
    closing
  } m_state = state::invalid;

  t_initiate_cb m_initiate_cb;

  std::unique_ptr<http_parser> m_http_parser;

  options m_options;

  std::string m_expected_accept_key;

  std::unique_ptr<websocketpp_impl> m_websock_impl;
};


}

#endif
