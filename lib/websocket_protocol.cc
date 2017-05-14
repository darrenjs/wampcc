/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/websocket_protocol.h"

#include "wampcc/utils.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/http_parser.h"
#include "wampcc/log_macros.h"
#include "wampcc/websocketpp_impl.h"

#include "apache/base64.h"

#include <string.h>
#include <assert.h>

#include <openssl/sha.h>

namespace wampcc
{

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
    m_websock_impl( new websocketpp_impl(mode) )
{
  // register with owner to receive heartbeat thread
  if (opts.ping_interval.count() > 0)
    callbacks.request_timer(opts.ping_interval);
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


static bool string_list_contains(const std::string & source,
                                 const std::string & match)
{

  for (auto & i : tokenize(source.c_str(), ',', true))
  {
    std::string trimmed = trim(i);
    if (case_insensitive_same(trimmed, match)) return true;
  }
  return false;
}


void websocket_protocol::send_msg(const json_array& ja)
{
  if (!have_codec())
    return;

  LOG_TRACE("fd: " << fd() << ", json_tx: " << ja);

  auto bytes = encode(ja);

  websocketpp::frame::opcode::value op{};
  switch (m_codec->type())
  {
    case serialiser_type::none: break;
    case serialiser_type::json: op = websocketpp::frame::opcode::text; break;
    case serialiser_type::msgpack: op = websocketpp::frame::opcode::binary; break;
  }

  // TODO: handle 0x00 opcode.  How to close the session?

  auto msg_ptr = m_websock_impl->msg_manager()->get_message(op,bytes.size());
  msg_ptr->append_payload(bytes.data(), bytes.size());
  auto out_msg_ptr = m_websock_impl->msg_manager()->get_message();

  // TODO: handle null outgoing_msg_ptr
//         if (!outgoing_msg) {
//             return error::make_error_code(error::no_outgoing_buffers);
//         }

  auto err = m_websock_impl->processor()->prepare_data_frame(msg_ptr, out_msg_ptr);

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

        if (not m_http_parser->good())
          throw handshake_error("bad http header: " + m_http_parser->error_text());

        if (m_http_parser->complete() )
        {
          if ( m_http_parser->is_upgrade() &&
               m_http_parser->has("Upgrade") &&
               string_list_contains(m_http_parser->get("Upgrade"), "websocket") &&
               m_http_parser->has("Connection") &&
               string_list_contains(m_http_parser->get("Connection"), "Upgrade") )
          {
            auto& websock_key = header_field("Sec-WebSocket-Key");
            auto& websock_ver = header_field("Sec-WebSocket-Version");
            auto& websock_sub = header_field("Sec-WebSocket-Protocol");

            if (websock_ver != RFC6455 /* 13 */)
              throw handshake_error("incorrect websocket version");

            /* determine the protocols common to both client and server */
            int common = m_options.serialisers &
              ((has_token(websock_sub,WAMPV2_JSON_SUBPROTOCOL)?serialiser_type::json:serialiser_type::none) |
               (has_token(websock_sub,WAMPV2_MSGPACK_SUBPROTOCOL)?serialiser_type::msgpack:serialiser_type::none));

            /* create the actual codec */
            create_codec(common);
            if (!m_codec)
              throw handshake_error("failed to negotiate websocket subprotocol");

            std::ostringstream os;
            os << "HTTP/1.1 101 Switching Protocols\r\n"
               << "Upgrade: websocket\r\n"
               << "Connection: Upgrade\r\n"
               << "Sec-WebSocket-Accept: " << make_accept_key(websock_key) << "\r\n"
               << "Sec-WebSocket-Protocol: " << to_header(m_codec->type()) << "\r\n"
               << "\r\n";
            std::string msg = os.str();

            LOG_TRACE("fd: " << fd() << ", http_tx: " << msg);

            m_socket->write(msg.c_str(), msg.size());
            m_state = state::open;
          }
          else
            throw handshake_error("http header is not a websocket upgrade");
        }
      }
      else if (m_state == state::open)
      {
        process_frame_bytes(rd);
      }
      else if (m_state == state::handling_http_response)
      {
        auto consumed = m_http_parser->handle_input(rd.ptr(), rd.avail());
        LOG_TRACE("fd: " << fd() << ", http_rx: " << std::string(rd.ptr(), consumed));
        rd.advance(consumed);

        if (not m_http_parser->good())
          throw handshake_error("bad http header: " + m_http_parser->error_text());

        if (m_http_parser->complete())
        {
          if ( m_http_parser->is_upgrade() &&
               m_http_parser->has("Upgrade") &&
               string_list_contains(m_http_parser->get("Upgrade"), "websocket") &&
               m_http_parser->has("Connection") &&
               string_list_contains(m_http_parser->get("Connection"), "Upgrade") &&
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

void websocket_protocol::send_ping()
{
  auto out_msg_ptr = m_websock_impl->msg_manager()->get_message();
  m_websock_impl->processor()->prepare_ping("", out_msg_ptr);

  LOG_TRACE("fd: " << fd() << ", frame_tx: " <<
            websocketpp_impl::frame_to_string(out_msg_ptr));

  assert(out_msg_ptr->get_payload().size() == 0); /* expect no payload */

  std::array< std::pair<const char*, size_t>, 1> bufs {
    {{ out_msg_ptr->get_header().data(), out_msg_ptr->get_header().size()}} };
  m_socket->write(bufs.data(), bufs.size());
}

void websocket_protocol::send_pong()
{
  auto out_msg_ptr = m_websock_impl->msg_manager()->get_message();
  m_websock_impl->processor()->prepare_pong("", out_msg_ptr);

  LOG_TRACE("fd: " << fd() << ", frame_tx: " <<
            websocketpp_impl::frame_to_string(out_msg_ptr));

  assert(out_msg_ptr->get_payload().size() == 0); /* expect no payload */

  std::array< std::pair<const char*, size_t>, 1> bufs {
    {{ out_msg_ptr->get_header().data(), out_msg_ptr->get_header().size()}} };
  m_socket->write(bufs.data(), bufs.size());
}



void websocket_protocol::on_timer()
{
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

  websocketpp::lib::error_code ec;
  size_t consumed = m_websock_impl->processor()->consume((uint8_t*) rd.ptr(), rd.avail(), ec);
  rd.advance(consumed);

  // TODO: check ec

  if (m_websock_impl->processor()->ready())
  {
    auto msg = m_websock_impl->processor()->get_message(); // shared_ptr<message_buffer::message<message_buffer::alloc::con_msg_manager> >

    if (!msg) {
      // raise failure
//        m_alog.write(log::alevel::devel, "null message from m_processor");
    } else if (!is_control(msg->get_opcode())) {

      // data message, dispatch to user

      // TODO: handle case of state closed but message arrived
//         if (m_state != session::state::open) {
//           //m_elog.write(log::elevel::warn, "got non-close frame while closing"

      LOG_TRACE("fd: " << fd() << ", frame_rx: " <<
                websocketpp_impl::frame_to_string(msg));

      if (msg->get_opcode() == websocketpp::frame::opcode::binary) {
        decode(msg->get_payload().data(), msg->get_payload().size());
      }
      else if (msg->get_opcode() == websocketpp::frame::opcode::text) {
        decode(msg->get_payload().data(), msg->get_payload().size());
      }

    } else {
      websocketpp::frame::opcode::value op = msg->get_opcode();

      if (op == websocketpp::frame::opcode::PING) {
        send_pong();
      } else if (op == websocketpp::frame::opcode::PONG) {

        /* Track loss of ping, after ping expected? */

      } else if (op == websocketpp::frame::opcode::CLOSE) {

        // TODO: need to reply with close ack frame

        // issue a close frame
        m_state = state::closing;

        // TODO: request for close should be initiaied from the owning session?

        m_socket->close();
      }

    }
  }





  // const frame::header hdr = frame::decode_header(rd.ptr(), rd.avail());

  // if (!hdr.complete || rd.avail() < hdr.frame_len())
  //   return;

  // LOG_TRACE("fd: " << fd() << ", frame_rx: " << hdr);

  // int const payload_pos = hdr.header_len;

  // for (size_t i = 0; i < (hdr.mask_bit?hdr.payload_len:0); ++i)
  //   rd[payload_pos+i] ^= hdr.mask[i%4];

  // if (!hdr.fin_bit)
  //   throw protocol_error("websocket continuations not supported");

  // switch (hdr.opcode)
  // {
  //   case OPCODE_CONTINUE: break;
  //   case OPCODE_TEXT: break;
  //   case OPCODE_BINARY: break;
  //   case OPCODE_CLOSE : {
  //     // issue a close frame
  //     m_state = state::closing;
  //     frame::header hdr(OPCODE_CLOSE, true, 0);
  //     auto hdr_buf = frame::encode_header(hdr);
  //     LOG_TRACE("fd: " << fd() << ", frame_tx: " << hdr);
  //     m_socket->write(hdr_buf.data(), hdr.header_len);

  //     // TODO: request for close should be initiaied from the owning session?
  //     m_socket->close();
  //     break;
  //   };
  //   default: break;
  // }

  // // TODO: when decoding text, should check for UTF8 complete string
  // if (hdr.fin_bit && hdr.opcode == OPCODE_TEXT)
  //   decode(rd.ptr()+payload_pos, hdr.payload_len);
  // else if (hdr.fin_bit && hdr.opcode == OPCODE_BINARY)
  //   decode(rd.ptr()+payload_pos, hdr.payload_len);

  // rd.advance(hdr.frame_len());
}

}
