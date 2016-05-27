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

// TODO: try and use pointers & forward decls in order to move the uv.h into the
// .cc file.
#include <uv.h>

namespace XXX {

class Logger;
class IOLoop;
class IOHandle;


typedef std::function<void(int port, IOHandle*)> socket_accept_cb;
typedef std::function<void(IOHandle*, int)> tcp_connect_cb;

// TODO: try to move to impl file
struct io_request
{
  Logger * logptr;
  std::string addr;
  int port = 0;
  std::unique_ptr< std::promise<int> > listener_err;
  uv_tcp_t * tcp_handle = nullptr;
  socket_accept_cb on_accept;
  tcp_connect_cb on_connect;
  io_request(Logger * __logptr) : logptr(__logptr) {}

  io_request(Logger * __logptr,
             int port,
             std::promise<int> p,
             socket_accept_cb );
};



struct  tcp_server
{
  uv_tcp_t uvh;
  int port;
  IOLoop * ioloop;
  socket_accept_cb cb;
};

// TODO: maybe the IO loop should also do the TCP connect stuff? I.e., it all goes there?
/* Intended to be a reusable event loop */
class IOLoop
{
public:
  IOLoop(Logger * logger);
  ~IOLoop();

  void start();
  void stop();
  void on_timer();
  void on_async();
  void run_loop();


  void async_send();

  void add_passive_handle(tcp_server* server, IOHandle* iohandle);
  void add_active_handle(IOHandle* iohandle, int status, io_request*);

  void add_server(int port, std::promise<int> listener_err, socket_accept_cb);

  void add_connection(std::string addr, int port, tcp_connect_cb);

  uv_loop_t* uv_loop() { return m_uv_loop; }

  Logger * logptr() const { return __logptr; }

private:
  Logger * __logptr;
  uv_loop_t*   m_uv_loop;
  std::unique_ptr<uv_timer_t> m_timer;
  std::unique_ptr<uv_async_t> m_async;
  std::thread  m_thread;
  bool m_async_closed = false;

private:

  void create_tcp_server_socket(int port, socket_accept_cb cb,
                                std::unique_ptr< std::promise<int> > );

  std::vector< std::unique_ptr<io_request> > m_pending_requests;
  std::mutex                                 m_pending_requests_lock;

  enum PendingFlags
  {
    eNone  = 0x00,
    eFinal = 0x01
  };
  int m_pending_flags;


  std::list< IOHandle* >m_handles; // TODO: need lock? No. Why not?


  std::list< std::unique_ptr<tcp_server> > m_server_handles;


};

} // namespace XXX


#endif
