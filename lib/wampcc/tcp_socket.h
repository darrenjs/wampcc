#ifndef WAMPCC_TCP_SOCKET_H
#define WAMPCC_TCP_SOCKET_H


#include <wampcc/kernel.h>
#include <wampcc/error.h>

#include <uv.h>

#include <string>
#include <future>
#include <iostream>
#include <vector>

#include <string.h>
#include <unistd.h>

namespace wampcc {

class io_loop;

/**
 * Represent a TCP socket, in both server mode and client mode.
 */
class tcp_socket
{
public:

  /** Type thrown by tcp_socket when actions are attempted when the socket is
   * not in an appropriate state. */
  class error : public std::runtime_error
  {
  public:
    error(std::string msg) : std::runtime_error(msg) {}
  };

  typedef std::function<void(char*, size_t)> io_on_read;
  typedef std::function<void(uverr)>         io_on_error;
  typedef std::function<void()> on_close_cb;
  typedef std::function<void(tcp_socket* server, std::unique_ptr<tcp_socket>& client, uverr)> on_accept_cb;

  tcp_socket(kernel* k);
  tcp_socket(kernel* k, uv_tcp_t*);
  ~tcp_socket();

  tcp_socket(const tcp_socket&) = delete;
  tcp_socket& operator=(const tcp_socket&) = delete;

  /** Request TCP connection to a remote end point.  This should only ever be
   * called once. */
  std::future<uverr> connect(std::string addr, int port);

  /** Request socket begins reading inbound data, with callbacks make on the IO
   * thread. */
  std::future<uverr> start_read(io_on_read, io_on_error);

  /** Reset IO callbacks */
  void reset_listener();

  /** Request a bind and listen */
  std::future<uverr> listen(int port, on_accept_cb);

  /* Request a write */
  void write(std::pair<const char*, size_t> * srcbuf, size_t count);

  /** Request asynchronous socket close. To detect when close has occured, the
   * caller can wait upon the returned future.  Throws io_loop_closed if IO loop
   * has already been closed. */
  std::shared_future<void> close();

  /** Request asynchronous socket reset & close.  */
  std::shared_future<void> reset();

  /** Request asynchronous socket close, and recieve notification via the
   * specified callback on the IO thread. If the tcp_socket is not currently
   * closed then the provided callback is invoked at the time of socket closure
   * and true is returned.  Otherwise, if the socket is already closed, the
   * callback is never invoked and false is returned. Throws io_loop_closed if
   * IO loop has already been closed. */
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

  enum class socket_state
  {
    init,
    connecting,
    connected,
    listening,
    closing,
    closed
  };

  tcp_socket(kernel* k, uv_tcp_t*, socket_state ss);
  void on_read_cb(ssize_t, const uv_buf_t*);
  void on_write_cb(uv_write_t *, int);
  void close_once_on_io();
  void do_write();
  void do_close(bool no_linger = false);
  void do_listen(int, std::shared_ptr<std::promise<uverr>>);
  void on_listen_cb(int);

  kernel * m_kernel;
  logger & __logger;

  uv_tcp_t* m_uv_tcp;

  socket_state       m_state;
  mutable std::mutex m_state_lock;

  std::unique_ptr< std::promise<void> > m_io_closed_promise;
  std::shared_future<void> m_io_closed_future;

  std::atomic<size_t> m_bytes_pending_write;
  size_t m_bytes_written;
  size_t m_bytes_read;

  io_on_read  m_io_on_read;
  io_on_error m_io_on_error;

  std::vector< uv_buf_t > m_pending_write;
  std::mutex              m_pending_write_lock;

  on_accept_cb            m_user_accept_fn;
  on_close_cb             m_user_close_fn;

  friend io_loop;
};

} // namespace wampcc

#endif
