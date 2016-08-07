#ifndef XXX_IOLOOP_H
#define XXX_IOLOOP_H

#include "Callbacks.h"

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
class io_handle;
class io_connector;
struct io_request;



typedef std::function<void(int port, std::unique_ptr<io_handle>)> socket_accept_cb;
typedef std::function<void(io_handle*, int)> tcp_connect_cb;

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

  void start();
  void stop();
  void on_timer();
  void on_async();
  void run_loop();


  void async_send();

  void add_passive_handle(tcp_server* server, io_handle* iohandle);

  void add_server(int port, std::promise<int> listener_err, socket_accept_cb);


  std::shared_ptr<io_connector> add_connection(std::string addr,
                                               std::string port,
                                               bool resolve_hostname);


  void request_cancel(uv_tcp_t*, uv_close_cb);

  uv_loop_t* uv_loop() { return m_uv_loop; }

  logger & get_logger() const { return __logger; }
  kernel & get_kernel() const { return m_kernel; }

private:
  kernel & m_kernel;
  struct logger & __logger;
  uv_loop_t*   m_uv_loop;
  std::unique_ptr<uv_async_t> m_async;
  std::thread  m_thread;
  bool m_async_closed = false;

private:

  void create_tcp_server_socket(int port, socket_accept_cb cb,
                                std::unique_ptr< std::promise<int> > );

  void on_tcp_connect_cb(uv_connect_t* __req, int status);

  std::vector< std::unique_ptr<io_request> > m_pending_requests;
  std::mutex                                 m_pending_requests_lock;

  void on_tcp_connect_cb();

  enum PendingFlags
  {
    eNone  = 0x00,
    eFinal = 0x01
  };
  int m_pending_flags;

  std::list< std::unique_ptr<tcp_server> > m_server_handles;
};

} // namespace XXX


#endif
