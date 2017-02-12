#ifndef WAMPCC_IOLOOP_H
#define WAMPCC_IOLOOP_H

#include "wampcc/utils.h"
#include "wampcc/error.h"

#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <list>
#include <memory>
#include <set>
#include <future>

#include <uv.h>

namespace wampcc {

class kernel;
struct logger;
class io_loop;
struct io_request;
class tcp_socket;

/** Can be called by user to wampcc library to check the compile-time version of
 * libuv is the same as when wampcc was compiled. */
void version_check_libuv(int uv_major, int uv_minor);

class uv_handle_data
{
public:
  enum { DATA_CHECK = 0x5555555555555555 };

  enum ptr_type {
    e_tcp_socket
  };

  uv_handle_data(ptr_type t, void* ptr)
    : m_check( DATA_CHECK ),
      m_type(t)
  {
    switch (t)
    {
      case e_tcp_socket:
        m_tcp_socket_ptr = (tcp_socket*) ptr;
        break;
    }
  }



  uint64_t check() const { return m_check; }
  ptr_type type() const { return m_type; }

  tcp_socket* tcp_socket_ptr() { return m_tcp_socket_ptr; }

private:
  uint64_t m_check; /* retain as first member */

  union {
    tcp_socket    * m_tcp_socket_ptr;
  };

  ptr_type m_type;
};


class io_loop_closed : public std::runtime_error
{
public:
  io_loop_closed();
};


/* IO Thread */
class io_loop
{
public:

  io_loop(kernel&, std::function<void()> io_starting_cb = nullptr);
  ~io_loop();

  /** Perform synchronous stop of the IO loop.  On return, the IO thread will
   * have been joined. */
  void sync_stop();

  void on_async();

  void connect(uv_tcp_t * handle,
               std::string addr,
               std::string port,
               bool resolve_hostname,
               std::function<void(uverr)> on_result);

  void cancel_connect(uv_tcp_t*);

  /** Push a function for later invocation on the IO thread.  Throws
   * io_loop_closed if the IO loop is closing or closed.
   */
  void push_fn(std::function<void()>);

  uv_loop_t* uv_loop() { return m_uv_loop; }

  logger & get_logger() const { return __logger; }
  kernel & get_kernel() const { return m_kernel; }

  /** Test whether current thread is the IO thread */
  bool this_thread_is_io() const;

private:

  void run_loop();

  void on_tcp_connect_cb(uv_connect_t* __req, int status);

  void push_request(std::unique_ptr<io_request>);

  kernel & m_kernel;
  struct logger & __logger;
  uv_loop_t*   m_uv_loop;
  std::unique_ptr<uv_async_t> m_async;

  enum {e_open, e_closing, e_closed}         m_pending_requests_state;
  bool                                       m_pending_requests_open;
  std::vector< std::unique_ptr<io_request> > m_pending_requests;
  std::mutex                                 m_pending_requests_lock;

  synchronized_optional<std::thread::id> m_io_thread_id;

  std::thread m_thread; // must be final member to prevent race conditions
};

} // namespace wampcc


#endif
