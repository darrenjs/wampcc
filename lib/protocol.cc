#include "XXX/protocol.h"

#include "XXX/io_handle.h"
#include "XXX/utils.h"
#include "XXX/rawsocket_protocol.h"
#include "XXX/websocket_protocol.h"
#include "XXX/http_parser.h"


#include <iostream>
#include <stdexcept>

#include <string.h>



namespace XXX {


  buffer::read_pointer::read_pointer(char * p, size_t avail)
    : m_ptr(p),
      m_avail(avail)
  {
  }

  buffer::buffer(size_t initial_size,
                 size_t max_size)
    : m_mem(initial_size),
      m_max_size(max_size),
      m_bytes_avail(0)
  {
  }


  void buffer::update_max_size(size_t new_max)
  {
    if (new_max == m_max_size) return;

    if ( (new_max < m_max_size) && (new_max < m_mem.size()) )
      throw std::runtime_error("unable to reduce buffer max size");

    m_max_size = new_max;

    // Note: don't perform any actual buffer modification, since it would
    // invalidate any read_pointer
  }


  size_t buffer::consume(const char* src, size_t len)
  {
    if (space() < len) grow_by(len-space());

    size_t consume_len = std::min(space(), len);
    if (consume_len == 0)
      throw std::runtime_error("buffer full, cannot consume more data");

    memcpy(m_mem.data() + m_bytes_avail, src, consume_len);
    m_bytes_avail += consume_len;

    return consume_len;
  }

  void buffer::grow_by(size_t len)
  {
    size_t grow_max  = m_max_size - m_mem.size();
    size_t grow_size = std::min(grow_max, len);
    if (grow_size)
      m_mem.resize(m_mem.size() + grow_size);
  }

  void buffer::discard_read(read_pointer rd)
  {
    m_bytes_avail = rd.avail();
    if (rd.ptr() != m_mem.data() && rd.avail())
      memmove(m_mem.data(), rd.ptr(), rd.avail());
  }


protocol::protocol(io_handle* h, t_msg_cb cb, connection_mode _mode)
  : m_iohandle(h),
    m_msg_processor(cb),
    m_buf(1,1024),
    m_mode(_mode)
{
}


void protocol::decode_json(const char* ptr, size_t msglen)
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


} // namespace
