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
#include "external/apache/base64.h"

#include <string.h>
#include <assert.h>

#include <openssl/sha.h>
#include <arpa/inet.h>

namespace wampcc
{

websocket_protocol::websocket_protocol(kernel* k,
                                       tcp_socket* h,
                                       t_msg_cb msg_cb,
                                       protocol::protocol_callbacks callbacks,
                                       connect_mode _mode,
                                       options opts)
  : protocol(k, h, msg_cb, callbacks, _mode),
    m_state(_mode==connect_mode::passive? state::handling_http_request : state::handling_http_response),
    m_http_parser(new http_parser(_mode==connect_mode::passive?
                                  http_parser::e_http_request : http_parser::e_http_response)),
    m_options(std::move(opts))
{
  m_rand_engine.reset(new std::mt19937(std::random_device()()));
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


// Two byte conversion union
union uint16_converter
{
    uint16_t i;
    uint8_t  m[2];
};

// Four byte conversion union
union uint32_converter
{
    uint32_t i;
    uint8_t m[4];
};

// Eight byte conversion union
union uint64_converter
{
    uint64_t i;
    uint8_t  m[8];
};


/* Websocket frame-header encoder and decoder */
struct frame
{
  // Maximum length of a WebSocket header (2+8+4)
  static unsigned int const MAX_HEADER_LENGTH = 14;
  static int const MASK_LEN = 4;

  static uint8_t const FRAME_OPCODE = 0x0F;
  static uint8_t const FRAME_FIN    = 0x80;
  static uint8_t const FRAME_MASKED = 0x80;
  static uint8_t const FRAME_PAYLOAD = 0x7F;


  struct header
  {
    bool complete;
    bool fin_bit;
    bool mask_bit;
    int opcode;
    uint8_t mask[4]; /* valid iff mask_bit set */
    size_t payload_len;
    size_t header_len;
    header() : complete(false){}

    header(int opcode__, bool fin__, size_t payload_len__, const uint8_t * mask__ = nullptr)
      : complete(true),
        fin_bit(fin__),
        mask_bit(mask__ != nullptr),
        opcode(opcode__),
        payload_len(payload_len__)
    {
      if (payload_len < 126)
        header_len = 2 + (mask_bit?4:0);
      else if (payload_len < 65536)
        header_len = 4 + (mask_bit?4:0);
      else
        header_len = 10 + (mask_bit?4:0);

      if (mask_bit)
        for (int i = 0; i < 4; i++)
          mask[i] = mask__[i];
    }

    size_t frame_len() const { return header_len + payload_len; }
    size_t mask_offset() const { return header_len - 4; }

    void to_stream(std::ostream& os) const
    {
      os << "fin " << fin_bit
         << ", opcode " << opcode
         << ", mask " << (mask_bit? to_hex((const char *)mask, 4) : "0")
         << ", header_len " << header_len
         << ", payload_len " << payload_len
         << ", frame_len " << (header_len+payload_len);
    }
  };

  static std::array<char, MAX_HEADER_LENGTH> encode_header(header& hdr)
  {
    std::array<char, MAX_HEADER_LENGTH> dest;
    encode_header(hdr, dest);
    return dest;
  }

  static void encode_header(header& hdr, std::array<char, MAX_HEADER_LENGTH>& dest)
  {
    dest[0] = (hdr.fin_bit?FRAME_FIN:0) | (FRAME_OPCODE & hdr.opcode);

    if (hdr.payload_len < 126)
      dest[1] = (unsigned char)(hdr.payload_len);
    else if (hdr.payload_len < 65536)
    {
      uint16_converter temp;
      temp.i = htons(hdr.payload_len & 0xFFFF);
      dest[1] = (unsigned char)126;
      dest[2] = temp.m[0];
      dest[3] = temp.m[1];
    }
    else
    {
      uint64_converter temp;
      temp.i = __bswap_64(hdr.payload_len);
      dest[1] = (unsigned char)127;
      for (int i = 0; i<8; ++i)
        dest[2+i]=temp.m[i];
    }

    if (hdr.mask_bit) {
      dest[1] |= FRAME_MASKED;
      for (int i = 0; i < 4; i++)
        dest[hdr.mask_offset()+i] = hdr.mask[i];
    }
  }

  static header decode_header(char src[], size_t len)
  {
    header p;

    if (len<2)
      return header(); /* frame header incomplete */

    p.fin_bit  = src[0] & FRAME_FIN;
    p.opcode   = src[0] & FRAME_OPCODE;
    p.mask_bit = src[1] & FRAME_MASKED;
    p.header_len = 2 + (p.mask_bit?4:0);

    if (len < p.header_len)
      return header(); /* frame header incomplete */

    p.payload_len = src[1] & FRAME_PAYLOAD;

    if (p.payload_len == 126) {
      p.header_len += 2;
      if (len < p.header_len)
        return header(); /* frame header incomplete */
      uint16_t raw_length;
      memcpy(&raw_length, &src[2], 2);
      p.payload_len = ntohs(raw_length);
    }
    else if (p.payload_len == 127) {
      p.header_len += 8;
      if (len < p.header_len)
        return header(); /* frame header incomplete */
      uint64_t raw_length;
      memcpy(&raw_length, &src[2], 8);
      p.payload_len = __bswap_64(raw_length);
    }

    if (p.mask_bit)
      for (int i = 0; i < 4; i++)
        p.mask[i] = src[p.header_len - 4 + i];

    p.complete = true;
    return p; /* header complete */
  }

};

std::ostream& operator<<(std::ostream& os, const wampcc::frame::header& hdr)
{
  hdr.to_stream(os);
  return os;
}

void websocket_protocol::send_msg(const json_array& ja)
{
  LOG_TRACE("fd: " << fd() << ", json_tx: " << ja);

  auto bytes = encode(ja);

  /* Only wamp client needs to apply a frame mask */
  bool use_mask = (mode() == connect_mode::active);

  uint32_converter mask;
  if (use_mask) {
    mask.i = std::uniform_int_distribution<uint32_t>()(*m_rand_engine);
    for (size_t i = 0; i < bytes.size(); ++i)
      bytes[i] ^= mask.m[i%4];
  }

  frame::header hdr(OPCODE_TEXT, true, bytes.size(), (use_mask?mask.m:nullptr));
  auto hdr_buf = frame::encode_header(hdr);

  LOG_TRACE("fd: " << fd() << ", frame_tx: " << hdr);

  std::pair<const char*, size_t> bufs[2] = {
    { hdr_buf.data(), hdr.header_len },
    { bytes.data(), bytes.size() } };

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
              ((has_token(websock_sub,WAMPV2_JSON_SUBPROTOCOL)?serialiser::json:serialiser::none) |
               (has_token(websock_sub,WAMPV2_MSGPACK_SUBPROTOCOL)?serialiser::msgpack:serialiser::none));

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
        const frame::header hdr = frame::decode_header(rd.ptr(), rd.avail());

        if (!hdr.complete || rd.avail() < hdr.frame_len())
          break;

        LOG_TRACE("fd: " << fd() << ", frame_rx: " << hdr);

        int const payload_pos = hdr.header_len;

        for (size_t i = 0; i < (hdr.mask_bit?hdr.payload_len:0); ++i)
          rd[payload_pos+i] ^= hdr.mask[i%4];

        if (!hdr.fin_bit)
          throw protocol_error("websocket continuations not supported");

        switch (hdr.opcode)
        {
          case OPCODE_CONTINUE: break;
          case OPCODE_TEXT:  break;
          case OPCODE_BINARY: {
            throw protocol_error("websocket binary messages not supported");
          }
          case OPCODE_CLOSE : {
            // issue a close frame
            m_state = state::closing;
            frame::header hdr(OPCODE_CLOSE, true, 0);
            auto hdr_buf = frame::encode_header(hdr);
            LOG_TRACE("fd: " << fd() << ", frame_tx: " << hdr);
            m_socket->write(hdr_buf.data(), hdr.header_len);

            // TODO: request for close should be initiaied from the owning session?
            m_socket->close();
            break;
          };
          default: break;
        }

        if (hdr.fin_bit && hdr.opcode == OPCODE_TEXT)
          decode(rd.ptr()+payload_pos, hdr.payload_len);

        rd.advance(hdr.frame_len());
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
              throw handshake_error("failed to negotiate websocket subprotocol");

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

  if (m_options.serialisers & serialiser::json)
    oss << WAMPV2_JSON_SUBPROTOCOL;
  if ((m_options.serialisers & serialiser::json) &&
      (m_options.serialisers & serialiser::msgpack))
    oss << ",";
  if (m_options.serialisers & serialiser::msgpack)
    oss << WAMPV2_MSGPACK_SUBPROTOCOL;
  oss << "\r\n";

  oss << "Sec-WebSocket-Version: " << RFC6455 << "\r\n\r\n";
  std::string http_request = oss.str();

  m_expected_accept_key = make_accept_key(sec_websocket_key);

  LOG_TRACE("fd: " << fd() << ", http_tx: " << http_request);
  m_socket->write(http_request.c_str(), http_request.size());
}

void websocket_protocol::on_timer()
{
  if (m_state == state::open)
  {
    frame::header hdr(OPCODE_PING, true, 0);
    auto hdr_buf = frame::encode_header(hdr);
    LOG_TRACE("fd: " << fd() << ", frame_tx: " << hdr);
    m_socket->write(hdr_buf.data(), hdr.header_len);
  }
}

serialiser websocket_protocol::to_serialiser(const std::string& s)
{
  if (s==WAMPV2_JSON_SUBPROTOCOL)
    return serialiser::json;
  else if (s==WAMPV2_MSGPACK_SUBPROTOCOL)
    return serialiser::json;
  else
    return serialiser::none;
}

const char* websocket_protocol::to_header(serialiser p)
{
  switch (p)
  {
    case serialiser::none: return "";
    case serialiser::json: return WAMPV2_JSON_SUBPROTOCOL;
    case serialiser::msgpack: return WAMPV2_MSGPACK_SUBPROTOCOL;
  }
  return "";
}

}
