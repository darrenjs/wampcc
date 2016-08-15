#include "XXX/rawsocket_protocol.h"

#include "XXX/io_handle.h"


#include <iostream>

namespace XXX {


static_assert(rawsocket_protocol::HEADER_SIZE==sizeof(uint32_t),
              "rawsocket header size must match 32 bit int");


rawsocket_protocol::rawsocket_protocol(io_handle* h,
                                         t_msg_cb msg_cb,
                                         connection_mode m)
  : protocol(h, msg_cb, m)
{
}


void rawsocket_protocol::initiate(t_initiate_cb cb)
{
  m_initiate_cb = cb;
  char header[ rawsocket_protocol::HEADER_SIZE ];
  header[0]=rawsocket_protocol::MAGIC;
  header[1]=0x21;
  header[2]=0;
  header[3]=0;
  std::pair<const char*, size_t> buf;
  buf.first  = &header[0];
  buf.second = 4;

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

      // TODO: I need more sophisicated state model in here, eg, to track
      // arrival of data before handshake is complete.

      if (m_state == ePendingHandshake)
      {
        if (mode() == connection_mode::ePassive)
        {
          if (rd[0] != MAGIC)
            throw std::runtime_error("rawsocket must begin with 0x7F");

          uint8_t serializer_type = rd[1] & 0x0F;
          uint8_t length_bits     = ((rd[1] & 0xF0)>>4) & 0x0F ;
          unsigned int client_max_msg_len = 1 << (9 + length_bits);

          std::cout << "client max length: " << client_max_msg_len << "\n";
          m_buf.update_max_size( client_max_msg_len );

          if ( (rd[2] bitor rd[3]) != 0)
            throw std::runtime_error("invalid rawsocket header");

          if (serializer_type != SERIALIZER_JSON && serializer_type != SERIALIZER_MSGPACK)
            throw std::runtime_error("unknown rawsocket serializer type");

          if (serializer_type == SERIALIZER_MSGPACK)
            throw std::runtime_error("msgpack not supported");

          // okay, reply with header
          std::cout << "replying to handshake request\n";
          std::pair<const char*, size_t> bufs[1];
          bufs[0].first  = rd.ptr();
          bufs[0].second = HEADER_SIZE;
          m_iohandle->write_bufs(bufs, 1, false);
        }
        else
        {
          std::cout << "rawsocket handshake complete" << "\n";
          // TODO: check the reply; the server might have rejected the handshake

          // TODO; set the max allowed buffer size

          // TODO: check the protocol serialiser type

          m_initiate_cb();
        }

        m_state = eHandshakeComplete;
        rd.advance(HEADER_SIZE);
      }
      else
      {
        // quick protocol check
        if ((rd.avail() > HEADER_SIZE) && ( rd[HEADER_SIZE] != '['))
          throw bad_protocol("bad json message");

        uint32_t msglen =  ntohl( *((uint32_t*) rd.ptr()) );
        if (rd.avail() < (HEADER_SIZE+msglen)) break; // body incomplete

        // TODO: what should this be checking?
        // if ((HEADER_SIZE+msglen) > m_buf.size())
        //   throw session_error(WAMP_RUNTIME_ERROR, "inbound message will exceed buffer");

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


}
