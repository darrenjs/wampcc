#ifndef XXX_PROTOCOL_H
#define XXX_PROTOCOL_H

#include "XXX/types.h"

#include <vector>
#include <cstddef>
#include <memory>

namespace XXX {

class tcp_socket;

class buffer
{
public:

  struct read_pointer
  {
    read_pointer(char *, size_t);

    char  operator[](size_t i) const { return m_ptr[i]; }
    char& operator[](size_t i)       { return m_ptr[i]; }

    void advance(size_t i) { m_ptr += i; m_avail -= i; }

    size_t avail() const { return m_avail; }

    const char * ptr() const { return m_ptr; }
          char * ptr()       { return m_ptr; }

  private:
    char * m_ptr;
    size_t m_avail;
  };


  buffer(size_t initial_size, size_t max_size);

  /** amount of actual data present */
  size_t data_size() const { return m_bytes_avail; }

  /** current space for new data */
  size_t space() const { return m_mem.size() - m_bytes_avail; }

  /** current buffer capacity */
  size_t capacity() const { return m_mem.size(); }

  /** pointer to data */
  char* data() { return m_mem.data(); }

  /** copy in new bytes, growing internal space if necessary */
  size_t consume(const char* src, size_t len);

  /** obtain a read pointer */
  read_pointer read_ptr() { return {m_mem.data(), m_bytes_avail}; }

  /** Update buffer to remove bytes that have be read via the read pointer. */
  void discard_read(read_pointer);

  void update_max_size(size_t);

private:

  void grow_by(size_t len);

  std::vector<char> m_mem;
  size_t m_max_size;
  size_t m_bytes_avail;
};

/** Exception thrown during IO processing of a new connection. This is an
 * unrecoverable error that prevents the correct construction of a protocol
 * encoder/decoder object, and so prevents creationg of a WAMP session from a
 * new socket connection.  Will lead to connection drop without any attempt to
 * send a final WAMP message (although protocol level messages maybe sent before
 * disconnect). */
class handshake_error : public std::runtime_error
{
public:
  handshake_error(const std::string& msg)
    : std::runtime_error(msg.c_str())
  {}
};

/** Exception thrown due to any sort of malformed WAMP message.  Generally this
 * error is thrown when the peer has failed to respect the terms of the WAMP
 * message-level protocol. Some examples: missinng mandatory arguments in WAMP
 * messages; values that have incorrect primitive type or container type (eg an
 * object where an array was expected).  This exception can be thrown during
 * initial message processing on the IO thread, or later during deferred
 * processing on the EV thread.  Shall result in a connection drop. */
class protocol_error : public std::runtime_error
{
public:
  protocol_error(const std::string& msg)
    : std::runtime_error(msg.c_str())
  {}

};

/* Base class for encoding & decoding of bytes on the wire. */
class protocol
{
public:

  struct options
  {
    std::string connect_host;
    std::string connect_port;
  };


  typedef std::function<void(jalson::json_array msg, int msgtype)> t_msg_cb;
  typedef std::function<void()> t_initiate_cb;

  enum class connection_mode
  {
      eActive,
      ePassive
  };

  protocol(tcp_socket*, t_msg_cb, connection_mode m);

  virtual int  required_timer_callback_interval_ms() { return 1000;}
  virtual void ev_on_timer() {}
  virtual void io_on_read(char*, size_t) = 0;
  virtual void initiate(t_initiate_cb) = 0;
  virtual const char* name() const = 0;

  virtual void send_msg(const jalson::json_array& j) = 0;

  connection_mode mode() const { return m_mode; }

protected:

  void decode_json(const char* ptr, size_t msglen);

  tcp_socket * m_socket; /* non owning */
  t_msg_cb    m_msg_processor;
  buffer m_buf;

private:
  connection_mode m_mode;
};

typedef std::function< std::unique_ptr<protocol> (tcp_socket*, protocol::t_msg_cb ) > protocol_builder_fn;


}


#endif
