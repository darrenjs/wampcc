#ifndef XXX_TCP_SOCKET_H
#define XXX_TCP_SOCKET_H


#include <XXX/kernel.h>

#include <uv.h>

#include <string>
#include <future>
#include <iostream>
#include <vector>

#include <string.h>
#include <unistd.h>

namespace XXX {

class io_listener;
class io_loop;

class auto_future
{
public:
  auto_future(std::shared_ptr<std::promise<void> > p)
    : m_auto_wait(true),
      m_promise(p),
      m_fut(p->get_future())
  {
  }

  auto_future(auto_future&& rhs)
  : m_promise(std::move(rhs.m_promise)),
    m_fut(std::move(rhs.m_fut))
  {
  }

  auto_future() = delete;
  auto_future(const std::future<void>& f) = delete;

  void set_auto_wait(bool b) { m_auto_wait=b;}

  ~auto_future()
  {
    if (m_auto_wait && m_fut.valid())
      m_fut.wait();
  }

  std::future<void> & get_future() { return m_fut; }

private:
  bool m_auto_wait;
  std::shared_ptr<std::promise<void> > m_promise;
  std::future<void> m_fut;
};

/**
 * Wrap a socket used for TCP stream communication
 */
class tcp_socket
{
public:
  tcp_socket(kernel* k);
  tcp_socket(kernel* k, uv_tcp_t*);
  ~tcp_socket();

  tcp_socket(const tcp_socket&) = delete;
  tcp_socket& operator=(const tcp_socket&) = delete;

  /** Request TCP connection to a remote end point */
  auto_future connect(std::string addr, int port);

  /** Request socket begins reading inbound data */
  void start_read(io_listener*);

  /** Request a bind and listen */
  void listen(int port);

  /* Enqueue bytes to be sent */
  void write(std::pair<const char*, size_t> * srcbuf, size_t count);

  /** Request socket close */
  std::shared_future<void> close();

  bool is_connected() const;
  bool is_closing()   const;
  bool is_closed()    const;

  /** Return underlying file description */
  int fd() const;

  size_t bytes_read()    const { return m_bytes_read; }
  size_t bytes_written() const { return m_bytes_written; }

private:

  enum socket_state
  {
    e_created,
    e_connected,
    e_closing,
    e_closed,
  };

  tcp_socket(kernel* k, uv_tcp_t*, socket_state ss);
  void on_read_cb(ssize_t, const uv_buf_t*);
  void on_write_cb(uv_write_t *, int);
  void close_once_on_io();
  void do_write();
  void do_close();

  kernel * m_kernel;
  logger & __logger;

  uv_tcp_t* m_uv_tcp;

  socket_state       m_state;
  mutable std::mutex m_state_lock;

  std::promise<void>       m_io_closed_promise;
  std::shared_future<void> m_io_closed_future;

  std::atomic<size_t> m_bytes_pending_write;
  size_t m_bytes_written;
  size_t m_bytes_read;

  io_listener * m_listener ;

  std::vector< uv_buf_t > m_pending_write;
  std::mutex              m_pending_write_lock;

  friend io_loop;
};

} // namespace XXX

#endif
