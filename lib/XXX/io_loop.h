#ifndef XXX_IOLOOP_H
#define XXX_IOLOOP_H

#include "XXX/types.h"

#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <list>
#include <memory>
#include <set>
#include <future>

#include <uv.h>

namespace XXX {

class kernel;
struct logger;
class io_loop;
struct io_request;
class tcp_socket;


// TODO: comment
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


/* IO Thread */
class io_loop
{
public:
  io_loop(kernel&);
  ~io_loop();

  void stop();

  void on_async();


  void connect(uv_tcp_t * handle,
               std::string addr,
               std::string port,
               bool resolve_hostname,
               std::function<void()> on_success,
               std::function<void(std::exception_ptr)> on_failure);

  void cancel_connect(uv_tcp_t*);

  void push_fn(std::function<void()>);

  uv_loop_t* uv_loop() { return m_uv_loop; }

  logger & get_logger() const { return __logger; }
  kernel & get_kernel() const { return m_kernel; }

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

  std::thread  m_thread; // should be final member
};

} // namespace XXX


#endif
