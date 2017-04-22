/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/rawsocket_protocol.h"

#include "wampcc/tcp_socket.h"
#include "wampcc/log_macros.h"

#include <sstream>

namespace wampcc {

template<int N>
static void format_handshake(char (&handshake) [N],
                             int max_size,
                             int serialiser)
{
  static_assert(rawsocket_protocol::HANDSHAKE_SIZE==4, "HANDSHAKE_SIZE must be 4");
  static_assert(N==4, "array size must be 4");

  handshake[0]=rawsocket_protocol::MAGIC;
  handshake[1]= ((max_size & 0xF) << 4) | (serialiser & 0xF);
  handshake[2]=0;
  handshake[3]=0;
}


const char* rawsocket_protocol::handshake_error_code_to_sting(handshake_error_code e)
{
  switch (e)
  {
    case e_SerialiserUnsupported :
      return  "serialised unsupported";
    case e_MaxMsgLengthUnacceptable :
      return "max msg length unacceptable";
    case e_UseOfReservedBits :
      return "use of handshake reserved bits";
    case e_MaxConnectionCountReach :
      return "max connection count reached";
    default:
      return "";
  }
}


rawsocket_protocol::rawsocket_protocol(kernel* k,
                                       tcp_socket* h,
                                       t_msg_cb msg_cb,
                                       protocol::protocol_callbacks callbacks,
                                       connect_mode __mode,
                                       options __options)
  : protocol(k, h, msg_cb, callbacks, __mode),
    m_options(__options),
    m_self_max_msg_size( 1<<(9+m_options.inbound_max_msg_size) ),
    m_peer_max_msg_size(0),
    m_last_pong(std::chrono::system_clock::now())
{
  m_buf.update_max_size(m_self_max_msg_size);

  if (__mode == connect_mode::active && __options.ping_interval.count() > 0)
    callbacks.request_timer(__options.ping_interval);
}


void rawsocket_protocol::initiate(t_initiate_cb cb)
{
  m_initiate_cb = cb;

  char handshake[HANDSHAKE_SIZE];

  int codecs = 0;
  codecs |= (m_options.serialisers & serialiser::json)? e_JSON : 0;
  codecs |= (m_options.serialisers & serialiser::msgpack)? e_MSGPACK : 0;

  format_handshake( handshake, m_options.inbound_max_msg_size, codecs);

  std::pair<const char*, size_t> buf;
  buf.first  = &handshake[0];
  buf.second = HANDSHAKE_SIZE;
  m_socket->write(&buf, 1);
}


void rawsocket_protocol::io_on_read(char* src, size_t len)
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
      if (m_state == eHandshaking)
      {
        if (rd.avail() < HANDSHAKE_SIZE)
          break;

        if (mode() == connect_mode::passive)
        {
          if (rd[0] != MAGIC)
            throw handshake_error("client handshake must begin with magic octet");

          uint8_t rd_1 = rd[1];
          m_peer_max_msg_size = 1 << (9 + (rd_1>>4) );

          if ((rd[2] || rd[3]))
          {
            reply_handshake(e_UseOfReservedBits, 0);
            throw handshake_error("handshake reserved bytes must be zero");
          }

          switch(rd_1 & 0x0F)
          {
            case e_JSON : break;
            case e_MSGPACK :
            default:
              reply_handshake(e_SerialiserUnsupported, 0);
              throw handshake_error("unsupported rawsocket serializer type");
          }

          // complete the handshake
          reply_handshake((int) m_options.inbound_max_msg_size, (int) e_JSON);
          m_state = eOpen;
        }
        else
        {
          if (rd[0] != MAGIC)
            throw handshake_error("server handshake must begin with magic octet");

          if ((rd[2] || rd[3]))
            throw handshake_error("server handshake reserved bytes must be zero");

          uint8_t rd_1 = rd[1];
          m_peer_max_msg_size = 1 << (9 + (rd_1>>4) );
          uint8_t serializer  = rd_1 & 0x0F;

          if (serializer == 0)
          {
            /* handshake rejected by server */

            auto error_code = (handshake_error_code) (rd_1 >> 4);
            std::ostringstream os;
            os << "server rejected handshake with error code " <<  error_code;
            const char* err_str = handshake_error_code_to_sting(error_code);
            if (err_str[0] != '\0')
              os << " (" << err_str << ")";
            throw handshake_error(os.str());
          }

          m_state = eOpen;
          m_initiate_cb();
        }

        rd.advance(HANDSHAKE_SIZE);
      }
      else
      {
        if (rd.avail() < FRAME_PREFIX_SIZE)
          break; // header incomplete

        uint32_t frame_hdr = ntohl( *((uint32_t*) rd.ptr()) );

        if (frame_hdr & FRAME_RESERVED_MASK)
          throw protocol_error("frame reserved bits must be zero");

        uint32_t msglen = frame_hdr & FRAME_MSG_LEN_MASK;

        if (msglen > m_self_max_msg_size)
          throw protocol_error("received message size exceeds limit");

        if (rd.avail() < (FRAME_PREFIX_SIZE+msglen))
          break; // body incomplete

        switch ((frame_hdr & FRAME_MSG_TYPE_MASK)>>FRAME_FIRST_OCTECT_SHIFT)
        {
          case MSG_TYPE_WAMP :
          {
            decode(rd.ptr()+FRAME_PREFIX_SIZE, msglen);
            break;
          }
          case MSG_TYPE_PING :
          {
            // on a ping, construct a pong that returns the payload, and
            // throttle the responses so as not to get overwhelmed by a peer
            auto now = std::chrono::system_clock::now();
            auto since_last_pong = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_pong);
            if (since_last_pong > std::chrono::seconds(5))
            {
              m_last_pong = now;
              uint32_t out_frame_hdr = msglen | (MSG_TYPE_PONG << FRAME_FIRST_OCTECT_SHIFT);
              out_frame_hdr = htonl(out_frame_hdr);
              std::pair<const char*, size_t> bufs[2];
              bufs[0].first  = (char*)&out_frame_hdr;
              bufs[0].second = FRAME_PREFIX_SIZE;
              if (msglen)
              {
                bufs[1].first  = rd.ptr()+FRAME_PREFIX_SIZE;
                bufs[1].second = msglen;
              }
              m_socket->write(bufs, msglen?2:1);
            }
            break;
          }
          case MSG_TYPE_PONG : break;
          default:
            throw protocol_error("unknown rawsocket msg type");
        };

        rd.advance(FRAME_PREFIX_SIZE+msglen); // advance to next message
      }
    }

    m_buf.discard_read( rd ); /* shift unused bytes to front of buffer */
  }

}


void rawsocket_protocol::send_msg(const json_array& ja)
{
  LOG_TRACE("fd: " << fd() << ", json_tx: " << ja);

  auto bytes = encode(ja);

  std::pair<const char*, size_t> bufs[2];

  uint32_t msglen = htonl(bytes.size());
  bufs[0].first  = (char*)&msglen;
  bufs[0].second = sizeof(msglen);

  bufs[1].first  = bytes.data();
  bufs[1].second = bytes.size();

  m_socket->write(bufs, 2);
}


void rawsocket_protocol::reply_handshake(int high, int low)
{
  char handshake[ HANDSHAKE_SIZE ];
  format_handshake(handshake, high, low);
  m_socket->write(handshake, HANDSHAKE_SIZE);
}


void rawsocket_protocol::on_timer()
{
  if (m_state == eOpen)
  {
    // Construct a ping message with an empty payload; the only bits set are the
    // TTT bits in the first octet.
    uint32_t out_frame_hdr = (MSG_TYPE_PING << FRAME_FIRST_OCTECT_SHIFT);
    out_frame_hdr = htonl(out_frame_hdr);
    m_socket->write((char*)&out_frame_hdr, FRAME_PREFIX_SIZE);
  }
}

}
