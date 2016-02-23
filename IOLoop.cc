#include "IOLoop.h"

#include "Logger.h"
#include "IOHandle.h"

#include <iostream>

#include <unistd.h>


namespace XXX {



/* Called on the IO thread when a ioreq attempt has completed */
static void __on_connect(uv_connect_t* __req, int status )
{
  std::unique_ptr<uv_connect_t> connect_req(__req);

  // IOLoop has set itself as the uv_loop data member
  IOLoop * ioloop = static_cast<IOLoop* >(__req->handle->loop->data);

  // get the user object
  std::unique_ptr<io_request> ioreq  (( io_request*) connect_req->data );
  Logger * __logptr = ioreq->logptr;

  if (status < 0)
  {
    // TODO: question for libuv: is there a way to get the errno ?
    _WARN_( "connect error, " <<  uv_strerror(status) );

    ioloop->add_active_handle(nullptr, status, ioreq.get());

    delete ioreq->tcp_connect;
  }
  else
  {

    IOHandle* ioh = new IOHandle( (uv_stream_t *) ioreq->tcp_connect,
                                  ioloop );
    ioloop->add_active_handle(ioh, 0, ioreq.get());
  }

}

static void __on_tcp_connect(uv_stream_t* server, int status)
{
  // IOLoop has set itself as the uv_loop data member
  IOLoop * myIOLoop = static_cast<IOLoop* >(server->loop->data);

  if (status < 0)
  {
    // TODO: logging
    fprintf(stderr, "New connection error %s\n", uv_strerror(status));
    return;
  }

  uv_tcp_t *client = new uv_tcp_t();
  uv_tcp_init(myIOLoop->uv_loop(), client);

  if (uv_accept(server, (uv_stream_t *) client) == 0)
  {
    IOHandle* ioh = new IOHandle( (uv_stream_t *) client, myIOLoop);

    int fd = client->io_watcher.fd;
    std::cout << "accept: type=" << client->type
              << ", fd=" << fd << "\n";

    if (client->type == UV_TCP)
    {
      std::cout << "got tcp fd "<<  fd<< "\n";
    }

    // register the stream before beginning read operations
    myIOLoop->add_passive_handle( ioh );

  //   // NOTE: registration of read event moved into the handle

  //   // // new client is accepted, identified via its stream handle ... need to put
  //   // // in place a lot more session tracking here.
  //   // uv_read_start((uv_stream_t *) client, alloc_buffer, io_on_read);
  }
  else
  {
    uv_close((uv_handle_t *) client, NULL);
  }

}


static void __io_async_cb(uv_async_t* handle)
{
  IOLoop* p = static_cast<IOLoop*>( handle->data );
  p->on_async();
}

static void __io_on_timer(uv_timer_t* handle)
{
  IOLoop* p = static_cast<IOLoop*>( handle->data );
  p->on_timer();
}

IOLoop::IOLoop(Logger * logptr,
               AsyncCallback timer_cb,
               AsyncCallback async_cb)
  : __logptr( logptr),
    m_uv_loop( new uv_loop_t() ),
    m_timer( new uv_timer_t() ),
    m_continue_loop(true),
    m_timer_cb ( timer_cb ),
    m_async_cb ( async_cb )
{
  uv_loop_init(m_uv_loop);
  m_uv_loop->data = this;

  // set up the async handler
  uv_async_init(m_uv_loop, &m_async, __io_async_cb);
  m_async.data = this;

  // set up timer

  uv_timer_init(m_uv_loop, m_timer.get());
  m_timer->data = this;
  uv_timer_start(m_timer.get(), __io_on_timer, 10, 10);

  // TODO: I prefer to not have to do this.  Need to review what is the correct
  // policy for handling sigpipe using libuv.
  //  signal(SIGPIPE, SIG_IGN);
}

void IOLoop::stop()
{
  m_continue_loop = false;
  async_send();
  m_thread.join();
}

IOLoop::~IOLoop()
{
  // TODO: in here, should I at least try to give the sockets once last attempt to gracefull close?

  if (m_continue_loop) stop();

  for (auto & item : m_handles) delete item;

  m_handles.clear();

  // uv_loop kept as raw pointer, because need to pass to several uv functions
  uv_loop_close(m_uv_loop);
  delete m_uv_loop;
  _INFO_("!!!!!! ub loop deleted");
}

void IOLoop::create_tcp_server_socket(int port)
{
  /* UV Loop */

  // Create a tcp socket, and configure for listen
  uv_tcp_t * server = new uv_tcp_t(); // TODO: what if this goes out of scope?
  uv_tcp_init(m_uv_loop, server);
  server->data = this;

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", port, &addr);

  unsigned flags = 0;
  uv_tcp_bind(server, (const struct sockaddr*)&addr, flags);
  int r = uv_listen((uv_stream_t *) server, 5, __on_tcp_connect);
  std::cout << "loop starting, r="<< r << "\n";

  m_server_handles.push_back( std::unique_ptr<uv_tcp_t>(server) );
}


void IOLoop::on_async()
{
  /* UV Loop */

  if (m_continue_loop==false)
  {
    uv_stop(m_uv_loop);
    return;
  }

  if (m_async_cb) m_async_cb();


  std::vector< io_request > work;
  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    work.swap( m_pending_requests );
  }

  for (auto & item : work)
  {
    if (item.addr.empty())
    {
      // TODO: check we dont already have port on this.
      create_tcp_server_socket(item.port);
    }
    else
    {
      std::unique_ptr<io_request> req( new io_request( item ) );
      req->tcp_connect = new uv_tcp_t();
      uv_tcp_init(m_uv_loop, req->tcp_connect);

      // use C++ allocator, so that I can vanilla unique_ptr
      uv_connect_t * connect_req = new uv_connect_t();
      connect_req->data = (void*) req.get();
      struct sockaddr_in dest;
      uv_ip4_addr(item.addr.c_str(), item.port, &dest);

      _INFO_("making TCP connection to " << item.addr.c_str() <<  ":" << item.port);
      int r = uv_tcp_connect(connect_req,
                             req->tcp_connect,
                             (const struct sockaddr*)&dest,
                             __on_connect);

      // TODO: I am not sure when to delete 'handle'
      if (r)
      {
        // libuv pattern: if a uv library function fails, then the callback will
        // not be registered and so wont get called.

        // TODO : return this error on the IO thread, eg we get an immediate error
        // if we try to connect to 227.43.0.1 although, I think it is better to
        // return it immediately.
        _INFO_ ("r=" << r );
      }
      else
      {
        _INFO_ ("r=" << r );
        // std::lock_guard<std::mutex> guard( m_handles_lock );
        // m_handles.push_back(handle.get());
        // handle.release();
        req.release();  //
      }

    }
  }

}

/* Any thread may enter here */
void IOLoop::async_send()
{
  // cause the IO thread to wake up
  uv_async_send( &this->m_async );
}

void IOLoop::run_loop()
{
  _INFO_("IO loop running");
  while ( m_continue_loop )
  {
    try
    {
      uv_run(m_uv_loop, UV_RUN_DEFAULT);
    }
    catch(...)
    {
      // TODO: log me properly
      std::cout << "exception in IOLoop thread\n";
    }
  }
}

void IOLoop::start()
{
  m_thread = std::thread(&IOLoop::run_loop, this);
}



void IOLoop::on_timer()
{
  if (m_timer_cb) m_timer_cb();

  bool need_remove = false;
  for (auto & item  : m_handles)
  {
    if (item->can_be_deleted())
    {
      delete item;
      item = nullptr;
      need_remove = true;
    }
  }
  if (need_remove) m_handles.remove( nullptr );
}

void IOLoop::add_server(int port)
{
  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    io_request r( __logptr );
    r.port = port;
    m_pending_requests.push_back( r );
  }

  this->async_send();
}

void IOLoop::add_connection(std::string addr,
                            int port,
                            tcp_connect_attempt_cb user_cb,
                            void* user_data)
{
  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock  );
    io_request r( __logptr );
    r.addr = addr;
    r.port = port;
    r.user_cb = user_cb;
    r.user_data = user_data;
    m_pending_requests.push_back( r );
  }

  this->async_send();
}

void IOLoop::add_passive_handle(IOHandle* iohandle)
{
  m_handles.push_back( iohandle );

  if (m_new_client_cb) m_new_client_cb( iohandle, 0, tcp_connect_attempt_cb(), nullptr );

}


/* Here we have completed a tcp connect attempt (either successfully or
 * unsuccessfully).  Next we shall escalate the result upto the handler.
 *
 */
void IOLoop::add_active_handle(IOHandle * iohandle, int status, io_request * req)
{
  if (iohandle) m_handles.push_back( iohandle );

  if (m_new_client_cb)
    m_new_client_cb( iohandle,
                     status,
                     req->user_cb,
                     req->user_data );



}




} // namespace XXX
