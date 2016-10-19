#ifndef XXX_TCP_SOCKET_H
#define XXX_TCP_SOCKET_H


#include <uv.h>
#include <XXX/kernel.h>

#include <string>
#include <future>
#include <iostream>

namespace XXX {

class io_listener;

class async_value
{
public:
  async_value(std::shared_ptr<std::promise<void> > p)
    : m_auto_wait(true),
      m_promise(p),
      m_fut(p->get_future())
  {
  }

  async_value(async_value&& rhs)
  : m_promise(std::move(rhs.m_promise)),
    m_fut(std::move(rhs.m_fut))
  {
  }

  async_value() = delete;
  async_value(const std::future<void>& f) = delete;

  void set_auto_wait(bool b) { m_auto_wait=b;}

  ~async_value()
  {
    if (m_auto_wait && m_fut.valid())
      m_fut.wait();
  }

  std::future<void>& get_future() { return m_fut; }


private:
  bool m_auto_wait;
  std::shared_ptr<std::promise<void>> m_promise;
  std::future<void> m_fut;
};

/**
 * Wrap a network socket
 */
class tcp_socket
{
public:
  tcp_socket(kernel* k);
  tcp_socket(const tcp_socket&) = delete;
  ~tcp_socket();
  tcp_socket& operator=(const tcp_socket&) = delete;

  /** Attempt to connect the socket to a remote end point */
  async_value connect(std::string addr, int port);

  bool is_connected() const;

  void do_close();

  /** Return underlying file description, for informational purposes. */
  int fd() const;

  /** Request socket begins reading inbound data */
  void start_read(io_listener*);

  /** Request socket close */
  void close();

private:

  void on_read_cb(ssize_t, const uv_buf_t*);

  kernel * m_kernel;
  uv_tcp_t* m_uv_tcp;

  enum socket_state
  {
    e_created,
    e_connected,
    e_closing,
    e_closed,
  } m_state;
  mutable std::mutex m_state_lock;

  std::promise<void>       m_io_closed_promise;
  std::shared_future<void> m_io_closed_future;

  size_t m_bytes_written;
  size_t m_bytes_read;

  io_listener * m_listener ;
};


} // namespace XXX

#endif
