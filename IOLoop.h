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

// TODO: try and use pointers & forward decls in order to move the uv.h into the
// .cc file.
#include <uv.h>

namespace XXX {

class Logger;
class IOLoop;
class IOHandle;



typedef std::function<void(IOHandle* ,int, int)> NewConnectionCallback;
typedef std::function<void(int port, IOHandle*)> socket_accept_cb;

// TODO: try to move to impl file
struct io_request
{
  std::string addr;
  int port = 0;
  uv_tcp_t * tcp_handle = nullptr;
  Logger * logptr;
  socket_accept_cb on_accept;
  t_connection_id user_conn_id = t_connection_id();
  io_request(Logger * __logptr) : logptr(__logptr) {}
};



struct  tcp_server
{
  uv_tcp_t uvh;
  int port;
  IOLoop * ioloop;
  char tmp[20480]; // TODO: delete me
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

  void add_server(int port, socket_accept_cb);
  // void add_connection(std::string addr, int port,
  //                     tcp_connect_attempt_cb, void*);

  void add_connection(std::string addr, int port,
                      t_connection_id);

  uv_loop_t* uv_loop() { return m_uv_loop; }


  Logger * logptr() const { return __logptr; }

private:
  Logger * __logptr;
  uv_loop_t*   m_uv_loop;
  std::unique_ptr<uv_timer_t> m_timer;
  std::unique_ptr<uv_async_t> m_async;
  std::thread  m_thread;
  bool m_async_closed = false;

public:
  NewConnectionCallback m_new_client_cb;

private:

  void create_tcp_server_socket(int port, socket_accept_cb cb);

  std::vector< io_request > m_pending_requests;
  std::mutex                m_pending_requests_lock;

  enum PendingFlags
  {
    eNone  = 0x00,
    eFinal = 0x01
  };
  int m_pending_flags;


  std::list< IOHandle* >m_handles; // TODO: need lock? No.


  std::list< std::unique_ptr<tcp_server> > m_server_handles;


};

} // namespace XXX


/*

#libuv

lubuv:  can I submit bytes to write, off the io_loop thread?

 Saul: The one and *only* thread-safe function is uv_async_send.

 */
#endif
