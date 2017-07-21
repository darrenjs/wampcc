/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/websocket_protocol.h"

#include "wampcc/platform.h"
#include "wampcc/utils.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/http_parser.h"
#include "wampcc/log_macros.h"
#include "wampcc/websocketpp_impl.h"

#include "apache/base64.h"

#include <string.h>
#include <assert.h>

#include <openssl/sha.h>

#define HTML_BODY "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"></head><body></body></html>"
#define HTML_BODY_LEN 86

static_assert(strlen(HTML_BODY)==HTML_BODY_LEN, "failed");

static const std::string http_200_response =
  "HTTP/1.1 200 OK\r\n"
  "Connection: close\r\n"
  "Content-Type: text/html; charset=UTF-8\r\n"
  "Content-Length: " STRINGIFY( HTML_BODY_LEN )  "\r\n\r\n"
  HTML_BODY;

namespace wampcc
{

/**
 * This struct is used to hide the websocketpp types from wampcc public
 * headers.
 */
struct websocketpp_msg
{
  websocket_config::message_type::ptr ptr;
};


websocket_protocol::websocket_protocol(kernel* k,
                                       tcp_socket* h,
                                       t_msg_cb msg_cb,
                                       protocol::protocol_callbacks callbacks,
                                       connect_mode mode,
                                       options opts)
  : protocol(k, h, msg_cb, callbacks, mode),
    m_state(mode==connect_mode::passive? state::handling_http_request : state::handling_http_response),
    m_http_parser(new http_parser(mode==connect_mode::passive?
                                  http_parser::e_http_request : http_parser::e_http_response)),
    m_options(std::move(opts)),
    m_websock_impl(new websocketpp_impl(mode)),
    m_last_pong(std::chrono::steady_clock::now())
{
  // register to receive heartbeat callbacks
  if (m_options.ping_interval.count() > 0)
    callbacks.request_timer(m_options.ping_interval);
}


inline std::string make_accept_key(const std::string& challenge)
{
  auto full_key = challenge + websocket_protocol::MAGIC;
  unsigned char obuf[20];

  SHA1((const unsigned char*)full_key.c_str(), full_key.size(), obuf);

  char tmp[50] = {0};
  assert(ap_base64encode_len(sizeof(obuf)) < (int)sizeof(tmp));
  assert(tmp[sizeof(tmp)-1] == 0);

  ap_base64encode(tmp, (char*)obuf, sizeof(obuf));

  return tmp;
}


/* Test whether a HTTP header contains a desired value.  Note that when checking
 * request and response headers, we are generally case
 * insensitive. I.e. according to RFC2616, all header field names in both HTTP
 * requests and HTTP responses are case-insensitive. */
static bool header_contains(const std::string & source,
                            const std::string & match)
{
  for (auto & i : tokenize(source.c_str(), ',', true))
  {
    std::string trimmed = trim(i);
    if (strcasecmp(trimmed.c_str(), match.c_str())==0)
      return true;
  }
  return false;
}


void websocket_protocol::send_msg(const json_array& ja)
{
  if (!have_codec())
    return;

  LOG_TRACE("fd: " << fd() << ", json_tx: " << ja);

  websocketpp::frame::opcode::value op{};
  switch (m_codec->type())
  {
    case serialiser_type::none: return;
    case serialiser_type::json: op = websocketpp::frame::opcode::text; break;
    case serialiser_type::msgpack: op = websocketpp::frame::opcode::binary; break;
  }

  auto bytes = encode(ja);

  auto msg_ptr = m_websock_impl->msg_manager()->get_message(op,bytes.size());
  msg_ptr->append_payload(bytes.data(), bytes.size());
  auto out_msg_ptr = m_websock_impl->msg_manager()->get_message();

  if (out_msg_ptr == nullptr)
    throw std::runtime_error("failed to obtain msg object");

  auto ec = m_websock_impl->processor()->prepare_data_frame(msg_ptr, out_msg_ptr);
  if (ec)
    throw std::runtime_error(ec.message());

  LOG_TRACE("fd: " << fd() << ", frame_tx: " <<
            websocketpp_impl::frame_to_string(out_msg_ptr));

  std::pair<const char*, size_t> bufs[2] = {
    { out_msg_ptr->get_header().data(), out_msg_ptr->get_header().size() },
    { out_msg_ptr->get_payload().data(), out_msg_ptr->get_payload().size()  } };

  m_socket->write(bufs, 2);
}


const std::string& websocket_protocol::header_field(const char* field) const
{
  if (!m_http_parser->has(field)) {
    std::string msg = "http header missing ";
    msg += field;
    throw handshake_error(msg);
  }
  else
    return m_http_parser->get(field);
}


void websocket_protocol::io_on_read(char* src, size_t len)
{
  /* IO thread */

  while(len)
  {
    size_t consume_len = m_buf.consume(src, len);
    src += consume_len;
    len -= consume_len;

    auto rd = m_buf.read_ptr();
    while (rd.avail())
    {
      if (m_state == state::handling_http_request)
      {
        auto consumed = m_http_parser->handle_input(rd.ptr(), rd.avail());
        LOG_TRACE("fd: " << fd() << ", http_rx: " << std::string(rd.ptr(), consumed));
        rd.advance(consumed);

        if (m_http_parser->good() == false)
          throw handshake_error("bad http header: " + m_http_parser->error_text());

        if (m_http_parser->complete())
        {
          if ( m_http_parser->is_upgrade() &&
               m_http_parser->has("Upgrade") &&
               header_contains(m_http_parser->get("Upgrade"), "websocket") &&
               m_http_parser->has("Connection") &&
               header_contains(m_http_parser->get("Connection"), "Upgrade") &&
               m_http_parser->has("Sec-WebSocket-Key") &&
               m_http_parser->has("Sec-WebSocket-Version") )
          {
            auto& websock_key = header_field("Sec-WebSocket-Key");
            auto& websock_ver = header_field("Sec-WebSocket-Version");

            if (websock_ver != RFC6455 /* 13 */)
              throw handshake_error("incorrect websocket version");

            bool sec_websocket_protocol_present = m_http_parser->has("Sec-WebSocket-Protocol");
            if (sec_websocket_protocol_present)
            {
              auto& websock_sub = header_field("Sec-WebSocket-Protocol");

              /* determine the protocols common to both client and server */
              int common = m_options.serialisers &
                ((has_token(websock_sub,WAMPV2_JSON_SUBPROTOCOL)?serialiser_type::json:serialiser_type::none) |
                 (has_token(websock_sub,WAMPV2_MSGPACK_SUBPROTOCOL)?serialiser_type::msgpack:serialiser_type::none));

              /* create the actual codec */
              create_codec(common);
            }
            else
              create_codec(static_cast<int>(serialiser_type::json));

            if (!m_codec)
              throw handshake_error("failed to negotiate websocket subprotocol");

            std::ostringstream os;
            os << "HTTP/1.1 101 Switching Protocols\r\n"
               << "Upgrade: websocket\r\n"
               << "Connection: Upgrade\r\n"
               << "Sec-WebSocket-Accept: " << make_accept_key(websock_key) << "\r\n";
            if (sec_websocket_protocol_present)
              os << "Sec-WebSocket-Protocol: " << to_header(m_codec->type()) << "\r\n";
            os<< "\r\n";
            std::string msg = os.str();

            LOG_TRACE("fd: " << fd() << ", http_tx: " << msg);

            m_socket->write(msg.c_str(), msg.size());
            m_state = state::open;
          }
          else if (m_http_parser->has("Connection") &&
                   header_contains(m_http_parser->get("Connection"), "close"))
          {
            /* Received a http header that requests connection close.  This is
             * straight-forward to obey (just echo the header and close the
             * socket). This kind of request can be received when connected to a
             * load balancer that is checking server health. */

            LOG_TRACE("fd: " << fd() << ", http_tx: " << http_200_response);
            m_socket->write(http_200_response.c_str(), http_200_response.size());
            m_state = state::closed;
            m_callbacks.protocol_closed();
          }
          else
            throw handshake_error("http header is not a websocket upgrade");
        }
      }
      else if (m_state == state::handling_http_response)
      {
        auto consumed = m_http_parser->handle_input(rd.ptr(), rd.avail());
        LOG_TRACE("fd: " << fd() << ", http_rx: " << std::string(rd.ptr(), consumed));
        rd.advance(consumed);

        if (m_http_parser->good() == false)
          throw handshake_error("bad http header: " + m_http_parser->error_text());

        if (m_http_parser->complete())
        {
          if ( m_http_parser->is_upgrade() &&
               m_http_parser->has("Upgrade") &&
               header_contains(m_http_parser->get("Upgrade"), "websocket") &&
               m_http_parser->has("Connection") &&
               header_contains(m_http_parser->get("Connection"), "Upgrade") &&
               m_http_parser->has("Sec-WebSocket-Accept")  &&
               m_http_parser->http_status_phrase() == "Switching Protocols" &&
               m_http_parser->http_status_code() == http_parser::status_code_switching_protocols)
          {
            auto& websock_key = header_field("Sec-WebSocket-Accept");
            auto& websock_sub = header_field("Sec-WebSocket-Protocol");

            if (websock_key != m_expected_accept_key)
              throw handshake_error("incorrect key for Sec-WebSocket-Accept");

            create_codec(m_options.serialisers & to_serialiser(websock_sub));

            if (!m_codec)
              throw handshake_error("failed to negotiate websocket message serialiser");

            m_state = state::open;
            m_initiate_cb();
          }
          else
            throw handshake_error("http header is not a websocket upgrade");
        }
      }
      else {
        /* for all other websocket states, use the websocketpp parser */
        process_frame_bytes(rd);
      }
    }

    m_buf.discard_read( rd ); /* shift unused bytes to front of buffer */
  }
}


void websocket_protocol::initiate(t_initiate_cb cb)
{
  m_initiate_cb = cb;

  char nonce [16];
  std::random_device rd;
  std::mt19937 engine( rd() );
  std::uniform_int_distribution<> distr(0x00, 0xFF);
  for (auto & x : nonce)
    x = distr(engine);

  char sec_websocket_key[30] = { 0 };
  assert(sec_websocket_key[sizeof(sec_websocket_key)-1] == 0);
  assert(ap_base64encode_len(sizeof(nonce)) < (int)sizeof(sec_websocket_key));

  ap_base64encode(sec_websocket_key, nonce, sizeof(nonce));

  std::ostringstream oss;
  oss <<
    "GET / HTTP/1.1\r\n"
    "Pragma: no-cache\r\n"
    "Cache-Control: no-cache\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Host: " << m_options.connect_host << ":" << m_options.connect_port <<  "\r\n"
    "Origin: " << hostname() << "\r\n"
    "Sec-WebSocket-Key: " << sec_websocket_key  << "\r\n"
    "Sec-WebSocket-Protocol: ";

  if (m_options.serialisers & serialiser_type::json)
    oss << WAMPV2_JSON_SUBPROTOCOL;
  if ((m_options.serialisers & serialiser_type::json) &&
      (m_options.serialisers & serialiser_type::msgpack))
    oss << ",";
  if (m_options.serialisers & serialiser_type::msgpack)
    oss << WAMPV2_MSGPACK_SUBPROTOCOL;
  oss << "\r\n";

  oss << "Sec-WebSocket-Version: " << RFC6455 << "\r\n\r\n";
  std::string http_request = oss.str();

  m_expected_accept_key = make_accept_key(sec_websocket_key);

  LOG_TRACE("fd: " << fd() << ", http_tx: " << http_request);
  m_socket->write(http_request.c_str(), http_request.size());
}


void websocket_protocol::send_impl(const websocketpp_msg& msg)
{
  LOG_TRACE("fd: " << fd() << ", frame_tx: " <<
            websocketpp_impl::frame_to_string(msg.ptr));

  if (msg.ptr->get_payload().empty()) {
    m_socket->write(msg.ptr->get_header().data(), msg.ptr->get_header().size());
  }
  else {
    std::pair<const char*, size_t> bufs[2] = {
      { msg.ptr->get_header().data(), msg.ptr->get_header().size() },
      { msg.ptr->get_payload().data(), msg.ptr->get_payload().size()  } };
    m_socket->write(bufs, 2);
  }
}


void websocket_protocol::send_ping()
{
  websocketpp_msg msg { m_websock_impl->msg_manager()->get_message() };
  m_websock_impl->processor()->prepare_ping("", msg.ptr);
  send_impl(msg);
}


void websocket_protocol::send_pong()
{
  websocketpp_msg msg { m_websock_impl->msg_manager()->get_message() };
  m_websock_impl->processor()->prepare_pong("", msg.ptr);
  send_impl(msg);
}


void websocket_protocol::send_close(uint16_t code, const std::string& reason)
{
  websocketpp_msg msg { m_websock_impl->msg_manager()->get_message() };
  m_websock_impl->processor()->prepare_close(code, reason, msg.ptr);
  send_impl(msg);
}


void websocket_protocol::on_timer()
{
  /* EV thread */
  if (m_state == state::open)
    send_ping();
}


serialiser_type websocket_protocol::to_serialiser(const std::string& s)
{
  if (s==WAMPV2_JSON_SUBPROTOCOL)
    return serialiser_type::json;
  else if (s==WAMPV2_MSGPACK_SUBPROTOCOL)
    return serialiser_type::msgpack;
  else
    return serialiser_type::none;
}


const char* websocket_protocol::to_header(serialiser_type p)
{
  switch (p)
  {
    case serialiser_type::none: return "";
    case serialiser_type::json: return WAMPV2_JSON_SUBPROTOCOL;
    case serialiser_type::msgpack: return WAMPV2_MSGPACK_SUBPROTOCOL;
  }
  return "";
}


void websocket_protocol::process_frame_bytes(buffer::read_pointer& rd)
{
  /* Feed bytes into the websocketpp stream parser. The parser will take only
   * the bytes required to build the next websocket message; it won't slurp all
   * the available bytes (i.e. its possible the consumed-count can be non-zero
   * after the consume() operation). */
  websocketpp::lib::error_code ec;
  size_t consumed = m_websock_impl->processor()->consume((uint8_t*) rd.ptr(), rd.avail(), ec);
  rd.advance(consumed);

  if (ec)
    throw std::runtime_error(ec.message());

  if (m_websock_impl->processor()->get_error())
    throw std::runtime_error("websocket parser fatal error");

  if (m_websock_impl->processor()->ready())
  {
    // shared_ptr<message_buffer::message<...> >
    auto msg = m_websock_impl->processor()->get_message();

    if (!msg)
      throw std::runtime_error("null message from websocketpp");

    LOG_TRACE("fd: " << fd() << ", frame_rx: " <<
              websocketpp_impl::frame_to_string(msg));

    if (m_state == state::closed)
      return; // ingore bytes after protocol closed

    if (!is_control(msg->get_opcode())) {
      // data message, dispatch to user
      if ((msg->get_opcode() == websocketpp::frame::opcode::binary) ||
          (msg->get_opcode() == websocketpp::frame::opcode::text)) {
        decode(msg->get_payload().data(), msg->get_payload().size());
      }
    } else {
      // control message
      websocketpp::frame::opcode::value op = msg->get_opcode();

      if (op == websocketpp::frame::opcode::PING) {
        const auto now = std::chrono::steady_clock::now();
        if ((now > m_last_pong) &&
            (now-m_last_pong >= m_options.ping_interval)) {
          m_last_pong = now;
          send_pong();
          return;
        }
      } else if (op == websocketpp::frame::opcode::PONG) {
        /* Track loss of ping, after ping expected? */
      } else if (op == websocketpp::frame::opcode::CLOSE) {
        if (m_state == state::closing) {
          // sent & received close-frame, so protocol closed
          m_state = state::closed;
          m_callbacks.protocol_closed();
        }
        if (m_state == state::open) {
          // received & sending close-frame, so protocol closed
          send_close(websocketpp::close::status::normal, "");
          m_state = state::closed;
          m_callbacks.protocol_closed();
        }
      }
    }
  }
}


bool websocket_protocol::initiate_close()
{
  /* Start the graceful close sequence. */
  m_state = state::closing;
  send_close(websocketpp::close::status::normal,"");
  return true;
}

}
