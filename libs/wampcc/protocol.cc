/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/protocol.h"

#include "wampcc/http_parser.h"
#include "wampcc/log_macros.h"
#include "wampcc/rawsocket_protocol.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/utils.h"
#include "wampcc/websocket_protocol.h"

#include <stdexcept>

#include <string.h>

namespace wampcc {

  class json_codec : public codec
  {
  public:
    json_value decode(const char* ptr, size_t msglen) override
    {
      json_value jv = wampcc::json_decode(ptr, msglen);
      return jv;
    }

    std::vector<char> encode(const json_array& src) override
    {
      std::string s = wampcc::json_encode(src);
      std::vector<char> retval(s.size());
      memcpy(retval.data(), s.c_str(), s.size());
      return retval;
    }

    serialiser_type type() const override { return serialiser_type::json;}
    const char* name() const override { return "json"; }
  };

  class msgpack_codec : public codec
  {
  public:
    json_value decode(const char* ptr, size_t msglen) override
    {
      json_value jv = wampcc::json_msgpack_decode(ptr, msglen);
      return jv;
    }

    std::vector<char> encode(const json_array& src) override
    {
      auto region = wampcc::json_msgpack_encode(src);
      std::vector<char> retval(region->second);
      memcpy(retval.data(), region->first, region->second);
      return retval;
    }

    serialiser_type type() const override { return serialiser_type::msgpack;}
    const char* name() const override { return "msgpack"; }
  };


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

    size_t consume_len = (std::min)(space(), len);
    if (len && consume_len == 0)
      throw std::runtime_error("buffer full, cannot consume data");

    memcpy(m_mem.data() + m_bytes_avail, src, consume_len);
    m_bytes_avail += consume_len;

    return consume_len;
  }

  void buffer::grow_by(size_t len)
  {
    size_t grow_max  = m_max_size - m_mem.size();
    size_t grow_size = (std::min)(grow_max, len);
    if (grow_size)
      m_mem.resize(m_mem.size() + grow_size);
  }

  void buffer::discard_read(read_pointer rd)
  {
    m_bytes_avail = rd.avail();
    if (rd.ptr() != m_mem.data() && rd.avail())
      memmove(m_mem.data(), rd.ptr(), rd.avail());
  }


  /* select & create a codec from range of choices */
  void protocol::create_codec(int choices)
  {
    if (choices & serialiser_type::msgpack)
      m_codec = std::shared_ptr<codec>(new msgpack_codec());
    else if (choices & serialiser_type::json)
      m_codec = std::shared_ptr<codec>(new json_codec());
  }

  protocol::protocol(kernel* kernel,
                     tcp_socket* h,
                     t_msg_cb cb,
                     protocol_callbacks callbacks,
                     connect_mode _mode,
                     size_t buf_initial_size,
                     size_t buf_max_size)
  : m_kernel(kernel),
    __logger(kernel->get_logger()),
    m_socket(h),
    m_msg_processor(cb),
    m_callbacks(callbacks),
    m_buf(buf_initial_size, buf_max_size),
    m_mode(_mode)
{
}


  std::string protocol::fd() const
{
  return m_socket->fd_info().second;
}


std::vector<char> protocol::encode(const json_array& ja)
{
  return m_codec?m_codec->encode(ja):std::vector<char>();
}


void protocol::decode(const char* ptr, size_t len)
{
  /* IO thread */
  try
  {
    json_value jv = m_codec->decode(ptr, len);

    LOG_TRACE("fd: " << fd() << ", json_rx: " << jv);

    json_array& msg = jv.as_array();

    if (msg.size() == 0)
      throw protocol_error("json array empty");

    if (!msg[0].is_uint())
      throw protocol_error("message type must be uint");

    m_msg_processor(msg, msg[0].as_uint());
  }
  catch( const json_error& e)
  {
    throw protocol_error(e.what());
  }
}

selector_protocol::selector_protocol(kernel* k, tcp_socket* sock,
                                     t_msg_cb msg_cb,
                                     protocol::protocol_callbacks callbacks,
                                     options opts)
  : protocol(k, sock, msg_cb, callbacks, connect_mode::passive,
             1, buffer_size_required()),
    m_opts(opts)
{
}


void selector_protocol::io_on_read(char* src, size_t len)
{
  while(len)
  {
    size_t consumed = m_buf.consume(src, len);
    src += consumed;
    len -= consumed;

    auto rd = m_buf.read_ptr();

    if (rd.avail() >= rawsocket_protocol::HANDSHAKE_SIZE
        && rd[0] == rawsocket_protocol::MAGIC)
    {
      if ((m_opts.protocols & static_cast<int>(protocol_type::rawsocket)) == 0)
        throw handshake_error("rawsocket protocol not enabled");

      rawsocket_protocol::options default_opts;
      default_opts.serialisers = m_opts.serialisers;
      std::unique_ptr<protocol> up (
        new rawsocket_protocol(m_kernel,
                               m_socket,
                               m_msg_processor,
                               m_callbacks,
                               connect_mode::passive,
                               default_opts) );
      protocol * new_proto_ptr = up.get();
      m_callbacks.upgrade_protocol(up);

      new_proto_ptr->io_on_read(m_buf.data(), m_buf.data_size());
      if (len)
        new_proto_ptr->io_on_read(src, len );
      break;
    }
    else if (rd.avail() >= websocket_protocol::HEADER_SIZE &&
             http_parser::is_http_get(rd.ptr(), rd.avail()))
    {
      if ((m_opts.protocols & static_cast<int>(protocol_type::websocket)) == 0)
        throw handshake_error("websocket protocol not enabled");

      websocket_protocol::options default_opts(m_opts);

      std::unique_ptr<protocol> up (
        new websocket_protocol(m_kernel,
                               m_socket,
                               m_msg_processor,
                               m_callbacks,
                               connect_mode::passive,
                               default_opts));
      protocol * new_proto_ptr = up.get();
      m_callbacks.upgrade_protocol(up);

      new_proto_ptr->io_on_read(m_buf.data(), m_buf.data_size());
      if (len)
        new_proto_ptr->io_on_read(src, len );
      break;
    }
    else if (rd.avail() >= buffer_size_required())
    {
      throw handshake_error("unknown wire protocol");
    }

    m_buf.discard_read( rd ); /* shift unused bytes to front of buffer */
  }
}


size_t selector_protocol::buffer_size_required()
{
  return (std::max)((size_t) rawsocket_protocol::HANDSHAKE_SIZE,
                    (size_t) websocket_protocol::HEADER_SIZE);
}

} // namespace
