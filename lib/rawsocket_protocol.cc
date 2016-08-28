#include "XXX/rawsocket_protocol.h"

#include "XXX/io_handle.h"


#include <iostream>

namespace XXX {


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


rawsocket_protocol::rawsocket_protocol(io_handle* h,
                                       t_msg_cb msg_cb,
                                       connection_mode __mode,
                                       options __options)
  : protocol(h, msg_cb, __mode),
    m_self_max_msg_size( 1<<(9+m_options.inbound_max_msg_size) ),
    m_peer_max_msg_size(0),
    m_options(__options)
{
  m_buf.update_max_size(m_self_max_msg_size);
}


void rawsocket_protocol::initiate(t_initiate_cb cb)
{
  m_initiate_cb = cb;

  char handshake[ HANDSHAKE_SIZE ];
  format_handshake( handshake, m_options.inbound_max_msg_size, e_JSON);

  std::pair<const char*, size_t> buf;
  buf.first  = &handshake[0];
  buf.second = HANDSHAKE_SIZE;
  m_iohandle->write_bufs(&buf, 1, false);
}


void rawsocket_protocol::io_on_read(char* src, size_t len)
{
  while (len) /* IO thread */
  {
    size_t consume_len = m_buf.consume(src, len);
    src += consume_len;
    len -= consume_len;

    auto rd = m_buf.read_ptr();
    while (rd.avail())
    {
      if (rd.avail() < rawsocket_protocol::HEADER_SIZE) break; // header incomplete

      if (m_state == eHandshaking)
      {
        if (rd.avail() < HANDSHAKE_SIZE) break;

        if (mode() == connection_mode::ePassive)
        {
          if (rd[0] != MAGIC)
            throw std::runtime_error("rawsocket client handshake must begin with magic octet");

          m_peer_max_msg_size = 1 << (9 + (rd[1]>>4) );
          uint8_t serializer  = rd[1] & 0x0F;

          if ((rd[2] || rd[3]))
          {
            reply_handshake(eUseOfReservedBits, 0);
            throw std::runtime_error("rawsocket handshake reserved bytes must be zero");
          }

          switch(serializer)
          {
            case e_JSON : break;
            case e_MSGPACK :
            default:
              reply_handshake(eSerialiserUnsupported, 0);
              throw std::runtime_error("unsupported rawsocket serializer type");
          }

          // complete the handshake
          reply_handshake((int) m_options.inbound_max_msg_size, (int) e_JSON);
          m_state = eOpen;
        }
        else
        {
          std::cout << "active connection received rawsocket handshake" << "\n";

          if (rd[0] != MAGIC)
            throw std::runtime_error("rawsocket server handshake reply must begin with magic octet");

          if ((rd[2] || rd[3]))
          {
            throw std::runtime_error("rawsocket server handshake reply reserved bytes must be zero");
          }

          m_peer_max_msg_size = 1 << (9 + (rd[1]>>4) );
          uint8_t serializer  = rd[1] & 0x0F;

          if (serializer == 0)
          {
            /* handshake rejected by server */

            // TODO: log error code
            // int error = rd[1] >> 4;

            throw std::runtime_error("server rejected handshake");
          }


          m_state = eOpen;
          m_initiate_cb();
        }

        rd.advance(HANDSHAKE_SIZE);
      }
      else
      {
        uint32_t msglen =  ntohl( *((uint32_t*) rd.ptr()) );
        if (rd.avail() < (HEADER_SIZE+msglen)) break; // body incomplete

        // TODO: test this
        if (msglen > m_self_max_msg_size)
        {
          throw std::runtime_error("inbound message size exceeds limit");
        }

        decode(rd.ptr()+HEADER_SIZE, msglen);
        rd.advance(HEADER_SIZE+msglen); // advance to next message
      }
    }

    m_buf.discard_read( rd ); /* shift unused bytes to front of buffer */
  } // while(len)

}


void rawsocket_protocol::decode(const char* ptr, size_t msglen)
{
  /* IO thread */
  try
  {
    jalson::json_value jv;
    jalson::decode(jv, ptr, msglen);

    jalson::json_array& msg = jv.as_array();

    if (msg.size() == 0)
      throw bad_protocol("json array empty");

    if (!msg[0].is_uint())
      throw bad_protocol("message type must be uint");

    m_msg_processor(msg, msg[0].as_uint());
  }
  catch( const jalson::json_error& e)
  {
    throw bad_protocol(e.what());
  }
}


void rawsocket_protocol::send_msg(const jalson::json_array& jv)
{
  std::pair<const char*, size_t> bufs[2];

  std::string msg ( jalson::encode( jv ) );

  uint32_t msglen = htonl(  msg.size() );
  bufs[0].first  = (char*)&msglen;
  bufs[0].second = sizeof(msglen);

  bufs[1].first  = (const char*)msg.c_str();
  bufs[1].second = msg.size();
  m_iohandle->write_bufs(bufs, 2, false);
}


void rawsocket_protocol::reply_handshake(int high, int low)
{
  char handshake[ HANDSHAKE_SIZE ];
  format_handshake(handshake, high, low);

  std::pair<const char*, size_t> bufs[1];
  bufs[0].first  = handshake;
  bufs[0].second = HANDSHAKE_SIZE;
  m_iohandle->write_bufs(bufs, 1, false);
}

}
