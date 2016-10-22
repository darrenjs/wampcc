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
class server_handle;
class tcp_socket;

typedef std::function<void(std::unique_ptr<server_handle>&)> on_server_socket_cb;
typedef std::function<void(int port, std::unique_ptr<tcp_socket>)> socket_accept_cb;


// TODO: comment
void version_check_libuv(int uv_major, int uv_minor);

/**
 * Wrap a libuv server socket.
 */
class server_handle
{
public:

  server_handle(uv_tcp_t*h, kernel * k);
  ~server_handle();

  void do_close();

  uv_tcp_t* m_uv_handle;

  void release();

  enum State
  {
    eOpen,
    eClosing,
    eClosed
  } m_state;
  std::mutex m_state_lock;
  std::promise<void>       m_io_has_closed;
  std::shared_future<void> m_shfut_io_closed;
  kernel * m_kernel;
};

class uv_handle_data
{
public:
  enum { DATA_CHECK = 0x5555555555555555 };

  enum ptr_type {
    io_handle_server,
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
      case io_handle_server:
        m_server_handle_ptr = (server_handle *) ptr;
        break;
    }
  }



  uint64_t check() const { return m_check; }
  ptr_type type() const { return m_type; }

  server_handle* server_handle_ptr() { return m_server_handle_ptr; }
  tcp_socket* tcp_socket_ptr() { return m_tcp_socket_ptr; }

private:
  uint64_t m_check; /* retain as first member */

  union {
    server_handle * m_server_handle_ptr;
    tcp_socket    * m_tcp_socket_ptr;
  };

  ptr_type m_type;
};

struct  tcp_server
{
  uv_tcp_t uvh;
  int port;
  io_loop * ioloop;
  socket_accept_cb cb;
};

/* IO Thread */
class io_loop
{
public:
  io_loop(kernel&);
  ~io_loop();

  void stop();

  void on_async();


  void add_passive_handle(tcp_server* server, tcp_socket* iohandle);

  void add_server(int port, std::promise<int> listener_err, on_server_socket_cb, socket_accept_cb);

  uv_tcp_t*  connect(std::string addr,
                     std::string port,
                     bool resolve_hostname,
                     std::function<void()> on_success,
                     std::function<void(std::exception_ptr)> on_failure);

  void connect2(uv_tcp_t * handle,
                std::string addr,
                std::string port,
                bool resolve_hostname,
                std::function<void()> on_success,
                std::function<void(std::exception_ptr)> on_failure);

  void cancel_connect(uv_tcp_t*);

  void close_server_handle(uv_tcp_t*);
  void close_tcp_socket(uv_tcp_t*);


  void push_fn(std::function<void()>);

  uv_loop_t* uv_loop() { return m_uv_loop; }

  logger & get_logger() const { return __logger; }
  kernel & get_kernel() const { return m_kernel; }

private:

  void run_loop();

  void create_tcp_server_socket(int port, socket_accept_cb cb,
                                std::unique_ptr< std::promise<int> > );

  void on_tcp_connect_cb(uv_connect_t* __req, int status);

  void push_request(std::unique_ptr<io_request>);

  kernel & m_kernel;
  struct logger & __logger;
  uv_loop_t*   m_uv_loop;
  std::unique_ptr<uv_async_t> m_async;

  std::vector< std::unique_ptr<io_request> > m_pending_requests;
  std::mutex                                 m_pending_requests_lock;


  enum PendingFlags
  {
    eNone  = 0x00,
    eFinal = 0x01
  };

  //std::list< std::unique_ptr<tcp_server> > m_server_handles;
  std::thread  m_thread; // should be final member
};

} // namespace XXX


#endif
