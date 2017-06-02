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
#include "external/apache/base64.h"

#include <iostream>

#include <string.h>
#include <assert.h>

#include <openssl/sha.h>

#define bswap_64(x) (                           \
    (((x) & 0xff00000000000000ull) >> 56) |     \
    (((x) & 0x00ff000000000000ull) >> 40) |     \
    (((x) & 0x0000ff0000000000ull) >> 24) |     \
    (((x) & 0x000000ff00000000ull) >> 8) |      \
    (((x) & 0x00000000ff000000ull) << 8) |      \
    (((x) & 0x0000000000ff0000ull) << 24) |     \
    (((x) & 0x000000000000ff00ull) << 40) |     \
    (((x) & 0x00000000000000ffull) << 56))

namespace wampcc
{

websocket_protocol::websocket_protocol(tcp_socket* h,
                                       t_msg_cb msg_cb,
                                       protocol::protocol_callbacks callbacks,
                                       connect_mode _mode,
                                       options opts)
  : protocol(h, msg_cb, callbacks, _mode),
    m_state(_mode==connect_mode::passive? eHandlingHttpRequest : eHandlingHttpResponse),
    m_http_parser(new http_parser(_mode==connect_mode::passive?
                                  http_parser::e_http_request : http_parser::e_http_response)),
    m_options(std::move(opts)),
    m_version(RFC6455)
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

struct frame_builder
{
  // Minimum length of a WebSocket frame header.
  static unsigned int const BASIC_HEADER_LENGTH = 2;

  // Maximum length of a WebSocket header (2+8+4)
  static unsigned int const MAX_HEADER_LENGTH = 14;

  static uint8_t const FRAME_OPCODE = 0x0F;
  static uint8_t const FRAME_FIN    = 0x80;
  static uint8_t const FRAME_MASKED = 0x80;


  /** Construct  */
  frame_builder(int opcode, bool is_fin, size_t payload_len, const uint8_t * mask = nullptr)
  {
    unsigned char is_fin_bit = is_fin?FRAME_FIN:0;

    m_image[0] = is_fin_bit | (FRAME_OPCODE & opcode);

    if (payload_len < 126)
    {
      m_image[1] = (unsigned char)(payload_len);
      m_header_len = 2;
    }
    else if (payload_len < 65536)
    {
      uint16_converter temp;
      temp.i = htons(payload_len & 0xFFFF);
      m_image[1] = (unsigned char)126;
      m_image[2] = temp.m[0];
      m_image[3] = temp.m[1];
      m_header_len = 4;
    }
    else
    {
      uint64_converter temp;
      temp.i = bswap_64(payload_len);
      m_image[1] = (unsigned char)127;
      for (int i = 0; i<8; ++i) m_image[2+i]=temp.m[i];
      m_header_len = 10;
    }

    if (mask) {
      m_image[1] |= FRAME_MASKED;
      m_image[m_header_len+0] = mask[0];
      m_image[m_header_len+1] = mask[1];
      m_image[m_header_len+2] = mask[2];
      m_image[m_header_len+3] = mask[3];
      m_header_len += 4;
    }
  }

  char * data() { return m_image; }
  const char * data() const { return m_image; }
  size_t size() const { return m_header_len; }

  std::pair<const char*, size_t> buf() const
  {
    return { data(), size() };
  }

private:

  // Storage for frame being created.
  char m_image[MAX_HEADER_LENGTH];

  // Actual frame size, since frame size depends on payload size and masking
  size_t m_header_len;
};



void websocket_protocol::send_msg(const json_array& ja)
{
  std::string msg ( json_encode( ja ) );

  /* Only wamp client needs to apply a frame mask */
  bool should_mask = (mode() == connect_mode::active);

  uint32_converter mask;
  if (should_mask) {
    std::uniform_int_distribution<uint32_t> distr;
    mask.i = distr(*m_rand_engine);
  }

  frame_builder fb(OPCODE_TEXT, true, msg.size(), (should_mask?mask.m:nullptr));

  std::pair<const char*, size_t> bufs[2];
  bufs[0] = fb.buf();
  bufs[1].first  = (const char*)msg.c_str();
  bufs[1].second = msg.size();

  if (should_mask)
    for (size_t i = 0; i < msg.size(); ++i)
      (const_cast<char*>(bufs[1].first))[i] ^= mask.m[i%4];

  m_socket->write(bufs, 2);
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
      if (m_state == eHandlingHttpRequest)
      {
        auto consumed = m_http_parser->handle_input(rd.ptr(), rd.avail());
        rd.advance(consumed);

        if (m_http_parser->good() == false)
          throw handshake_error("bad http header: " + m_http_parser->error_text());

        if (m_http_parser->complete() )
        {
          if ( m_http_parser->is_upgrade() &&
               m_http_parser->has("Upgrade") &&
               header_contains(m_http_parser->get("Upgrade"), "websocket") &&
               m_http_parser->has("Connection") &&
               header_contains(m_http_parser->get("Connection"), "Upgrade") &&
               m_http_parser->has("Sec-WebSocket-Key") &&
               m_http_parser->has("Sec-WebSocket-Version") )
          {
            auto websocket_version = std::stoi(m_http_parser->get("Sec-WebSocket-Version").c_str());

            // TODO: hande version 0 ?

            if (websocket_version == 13) // RFC6455
            {
              std::ostringstream os;
              os << "HTTP/1.1 101 Switching Protocols" << "\r\n";
              os << "Upgrade: websocket" << "\r\n";
              os << "Connection: Upgrade" << "\r\n";
              os << "Sec-WebSocket-Accept: " << make_accept_key(m_http_parser->get("Sec-WebSocket-Key")) << "\r\n";
              os << "Sec-WebSocket-Protocol: " << subprotocol_header() << "\r\n";
              os << "\r\n";

              std::string msg = os.str();
              std::pair<const char*, size_t> buf;
              buf.first  = msg.c_str();
              buf.second = msg.size();

              m_socket->write(&buf, 1);
              m_state = eOpen;
            }
            else
            {
              throw handshake_error("unsupported websocket version");
            }
          }
          else
            throw handshake_error("http header is not a websocket upgrade");
        }
      }
      else if (m_state == eOpen)
      {
        if (rd.avail() < 2) break;

        bool       fin_bit = (rd[0] & 0x80) > 0;
        int         opcode = rd[0] & 0x0F;
        bool      mask_bit = (rd[1] & 0x80) > 0;
        size_t payload_len = rd[1] & 0x7F;
        size_t   frame_len = 2 + (mask_bit? 4:0);
        int       mask_pos = 2;
        int    payload_pos;

        if (payload_len == 126)
        {
          if (rd.avail() < 4) break;
          frame_len   += 2;
          mask_pos    += 2;
          uint16_t raw_length;
          memcpy(&raw_length, &rd[2], 2);
          payload_len = ntohs(raw_length);
        }
        else if (payload_len == 127)
        {
          if (rd.avail() < 10) break;
          frame_len   += 8;
          mask_pos    += 8;

          uint64_t raw_length;
          memcpy(&raw_length, &rd[2], 8);
          payload_len = bswap_64(raw_length);
        }
        frame_len += payload_len;
        payload_pos = mask_pos + (mask_bit? 4:0);

        if (rd.avail() < frame_len) break;

        for (size_t i = 0; i < (mask_bit?payload_len:0); ++i)
          rd[payload_pos+i] ^= rd[mask_pos + (i%4)];

        //std::cout << "fin=" << fin_bit << ", opcode=" << opcode << ", "
        //          << "framelen=" << frame_len << ", ";
        //if (mask_bit) std::cout << "mask=" << to_hex(&rd[mask_pos], 4) << ", ";
        //std::cout << "payloadlen=" << payload_len << ", ";

        std::string payload(&rd[payload_pos], payload_len);
        //std::cout << "payload=" << payload << "\n";

        if (!fin_bit)
          throw protocol_error("websocket continuations not yet supported");

        switch (opcode)
        {
          case 0x00: /* cont. */ break;
          case 0x01: /* text  */ break;
          case 0x02: /* bin.  */
          {
            throw protocol_error("websocket binary messages not supported");
          }
          case OPCODE_CLOSE :
          {
            // issue a close frame
            m_state = eClosing;
            frame_builder fb(OPCODE_CLOSE, true, 0);
            auto buf = fb.buf();
            m_socket->write(&buf, 1);

            // TODO: request for close should be initiaied from the owning session?
            m_socket->close();
            break;
          };
          default: break;
        }

        if (fin_bit && opcode == OPCODE_TEXT)
          decode_json(rd.ptr()+payload_pos, payload_len);

        rd.advance(frame_len);
      }
      else if (m_state == eHandlingHttpResponse)
      {
        auto consumed = m_http_parser->handle_input(rd.ptr(), rd.avail());
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
            auto sec_websocket_accept = m_http_parser->get("Sec-WebSocket-Accept");

            if (sec_websocket_accept != m_expected_accept_key)
              throw handshake_error("Sec-WebSocket-Accept incorrect");

            // std::cout << "*** upgrade ok ***\n";
            m_state = eOpen;
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
  oss << "GET / HTTP/1.1\r\n"
         "Pragma: no-cache\r\n"
         "Cache-Control: no-cache\r\n"
         "Upgrade: websocket\r\n"
         "Connection: Upgrade\r\n"
      << "Host: " << m_options.connect_host << ":" << m_options.connect_port <<  "\r\n"
      << "Origin: " << hostname() << "\r\n"
      << "Sec-WebSocket-Key: " << sec_websocket_key  << "\r\n"
      << "Sec-WebSocket-Protocol: "<< subprotocol_header() << "\r\n"
      << "Sec-WebSocket-Version: " << m_version << "\r\n"
         "\r\n";
  std::string http_request = oss.str();

  m_expected_accept_key = make_accept_key(sec_websocket_key);

  std::pair<const char*, size_t> bufs[1];
  bufs[0].first  = http_request.c_str();
  bufs[0].second = http_request.size();

  m_socket->write(bufs, 1);
}


void websocket_protocol::on_timer()
{
  if (m_state == eOpen)
  {
    frame_builder fb(OPCODE_PING, true, 0);
    auto buf = fb.buf();
    m_socket->write(&buf, 1);
  }
}

const char* websocket_protocol::subprotocol_header()
{
  // TODO: needs to be smarter, when wampcc has support for msgpack
  return WAMPV2_JSON_SUBPROTOCOL;
}

}
