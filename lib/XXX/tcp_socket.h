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


/**
 * Wrap a socket used for TCP stream communication
 */
class tcp_socket
{
  typedef std::function<void()> on_close_cb;
  typedef std::function<void(tcp_socket* socket, int status)> on_connect_cb;
  typedef std::function<void(tcp_socket* server, std::unique_ptr<tcp_socket>& client, int status)> on_accept_cb;

public:

  tcp_socket(kernel* k);
  tcp_socket(kernel* k, uv_tcp_t*);
  ~tcp_socket();

  tcp_socket(const tcp_socket&) = delete;
  tcp_socket& operator=(const tcp_socket&) = delete;

  /** Request TCP connection to a remote end point */
  std::future<void> connect(std::string addr, int port);
  void              connect(std::string addr, int port, on_connect_cb);

  /** Request socket begins reading inbound data */
  void start_read(io_listener*);

  /** Request a bind and listen */
  std::future<int> listen(int port, on_accept_cb);

  /* Request a write */
  void write(std::pair<const char*, size_t> * srcbuf, size_t count);

  /** Request socket close */
  std::shared_future<void> close();

  bool close(on_close_cb);

  bool is_connected() const;
  bool is_listening() const;
  bool is_closing()   const;
  bool is_closed()    const;

  /** Return underlying file description */
  int fd() const;

  size_t bytes_read()    const { return m_bytes_read; }
  size_t bytes_written() const { return m_bytes_written; }

  std::shared_future<void> closed_future() const { return m_io_closed_future; }

private:

  enum socket_state
  {
    e_init,
    e_connected,
    e_listening,
    e_closing,
    e_closed,
  };

  tcp_socket(kernel* k, uv_tcp_t*, socket_state ss);
  void on_read_cb(ssize_t, const uv_buf_t*);
  void on_write_cb(uv_write_t *, int);
  void close_once_on_io();
  void do_write();
  void do_close();
  void do_listen(int, std::shared_ptr<std::promise<int>>);
  void on_listen_cb(int);

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

  on_accept_cb            m_user_accept_fn;
  on_close_cb             m_user_close_fn;

  friend io_loop;
};

} // namespace XXX

#endif
