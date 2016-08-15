#ifndef XXX_PROTOCOL_H
#define XXX_PROTOCOL_H

#include "XXX/types.h"

#include <vector>
#include <cstddef>
#include <memory>

namespace XXX {

class io_handle;
class wamp_session;


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
  size_t avail() const { return m_bytes_avail; }

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



class bad_protocol : public std::runtime_error
{
public:
  bad_protocol(const std::string& msg)
    : std::runtime_error(msg.c_str())
  {}

};

/* Base class for encoding & decoding of bytes on the wire. */
class protocol
{
public:

  typedef std::function<void(jalson::json_array msg, int msgtype)> t_msg_cb;
  typedef std::function<void()> t_initiate_cb;

  enum class connection_mode
  {
      eActive,
      ePassive
  };

  protocol(io_handle*, t_msg_cb, connection_mode m);

  virtual int  required_timer_callback_interval_ms() { return 1000;}
  virtual void ev_on_timer() {}
  virtual void io_on_read(char*, size_t) = 0;
  virtual void initiate(t_initiate_cb) = 0;

  virtual void encode(const jalson::json_array& j) {}

  connection_mode mode() const { return m_mode; }

protected:

  void decode_json(const char* ptr, size_t msglen);

  io_handle * m_iohandle; /* non owning */
  t_msg_cb    m_msg_processor;
  buffer m_buf;

private:
  connection_mode m_mode;
};


class factory_protocol : public protocol
{
public:

  typedef std::function<void(std::unique_ptr<protocol>, char*, size_t)> t_swtich_fn;

  factory_protocol(io_handle*, t_msg_cb, t_swtich_fn);
  virtual int  required_timer_callback_interval_ms() override { return 0;}
  virtual void ev_on_timer() {}
  virtual void io_on_read(char*, size_t) override;
  virtual void initiate(t_initiate_cb) override;

private:
  t_swtich_fn m_protocol_change_fn;
};




}


#endif
