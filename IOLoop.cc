#include "IOLoop.h"

#include "io_connector.h"
#include "Logger.h"
#include "IOHandle.h"
#include "kernel.h"

#include <iostream>
#include <system_error>

#include <unistd.h>
#include <string.h>


#define SYSTEM_HEARTBEAT_MS 10

namespace XXX {


void IOLoop::on_tcp_connect_cb(uv_connect_t* connect_req, int status)
{
  /* IO thread */

  std::unique_ptr<io_request> ioreq ((io_request*) connect_req->data );

  if (status < 0)
  {
    ioreq->connector->io_on_connect_exception(
      std::make_exception_ptr( std::system_error(abs(status), std::system_category()) )
      );
  }
  else
  {
    ioreq->connector->io_on_connect_success();
  }
}


static void __on_tcp_connect(uv_stream_t* server, int status)
{
  // IOLoop has set itself as the uv_loop data member
  tcp_server* myserver = (tcp_server*) server;
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
    IOHandle* ioh = new IOHandle( myIOLoop->logptr(),
                                  (uv_stream_t *) client, myIOLoop);

    int fd = client->io_watcher.fd;
    std::cout << "accept: type=" << client->type
              << ", fd=" << fd << "\n";

    if (client->type == UV_TCP)
    {
      std::cout << "got tcp fd "<<  fd<< "\n";
    }

    // register the stream before beginning read operations
    myserver->ioloop->add_passive_handle(myserver, ioh );

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






io_request::io_request(Logger * lp,
                       int __port,
                       std::promise<int> listen_err,
                       socket_accept_cb __on_accept)
  : logptr( lp ),
    port( __port ),
    listener_err( new std::promise<int>(std::move(listen_err) ) ),
    on_accept( std::move(__on_accept) ),
    request_type( eNone )
{
}


IOLoop::IOLoop(kernel& k)
  :  m_kernel(k),
     __logptr( k.get_logger() ),
    m_uv_loop( new uv_loop_t() ),

    m_async( new uv_async_t() ),
    m_pending_flags( eNone )
{
  uv_loop_init(m_uv_loop);
  m_uv_loop->data = this;

  // set up the async handler
  uv_async_init(m_uv_loop, m_async.get(), [](uv_async_t* h) {
      IOLoop* p = static_cast<IOLoop*>( h->data );
      p->on_async();
    });
  m_async->data = this;

  // TODO: I prefer to not have to do this.  Need to review what is the correct
  // policy for handling sigpipe using libuv.
  //  signal(SIGPIPE, SIG_IGN);
}

void IOLoop::stop()
{
  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    m_pending_flags |= eFinal;
  }
  async_send();
  if (m_thread.joinable()) m_thread.join();
}

IOLoop::~IOLoop()
{
  // uv_loop kept as raw pointer, because need to pass to several uv functions
  uv_loop_close(m_uv_loop);
  delete m_uv_loop;
}

void IOLoop::create_tcp_server_socket(int port,
                                      socket_accept_cb cb,
                                      std::unique_ptr< std::promise<int> > listener_err )
{
  /* UV Loop */

  // Create a tcp socket, and configure for listen
  tcp_server * myserver = new tcp_server();
  myserver->port   = port;
  myserver->ioloop = this;
  myserver->cb = cb;

  uv_tcp_init(m_uv_loop, &myserver->uvh);

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", port, &addr);

  unsigned flags = 0;
  int r;

  r = uv_tcp_bind(&myserver->uvh, (const struct sockaddr*)&addr, flags);
  if (r == 0)
    r = uv_listen((uv_stream_t *) &myserver->uvh, 5, __on_tcp_connect);
  listener_err->set_value(std::abs(r));

  m_server_handles.push_back( std::unique_ptr<tcp_server>(myserver) );
}


void IOLoop::on_async()
{
  /* IO thread */
  std::vector< std::unique_ptr<io_request> > work;
  int pending_flags = eNone;

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    work.swap( m_pending_requests );
    std::swap(pending_flags, m_pending_flags);
  }

  if (m_async_closed) return;

  if (pending_flags & eFinal)
  {
    for (auto & i : m_handles)
      i->request_close();

    for (auto & i : m_server_handles)
      uv_close((uv_handle_t*)i.get(), 0);

    uv_close((uv_handle_t*) m_async.get(), 0);

    m_async_closed = true;
    return;
  }

  for (auto & user_req : work)
  {
    if (user_req->request_type == io_request::eCancelHandle)
    {
      uv_close((uv_handle_t*) user_req->tcp_handle, user_req->on_close_cb);
    }
    else if (user_req->connector)
    {
      // create the request
      std::unique_ptr<io_request> req( std::move(user_req) );  // <--- the sp<connector> is here now

      // TODO: check connect_req * req are both freed correctly

      uv_connect_t * connect_req = new uv_connect_t();
      connect_req->data = (void*) req.get();

      struct sockaddr_in dest;
      memset(&dest, 0, sizeof(sockaddr_in));
      uv_ip4_addr(req->addr.c_str(), req->port, &dest);

      _INFO_("making new tcp connection to " << req->addr.c_str() <<  ":" << req->port);
      int r = uv_tcp_connect(
        connect_req,
        req->connector->get_handle(),
        (const struct sockaddr*) &dest,
        [](uv_connect_t* __req, int status)
        {
          std::unique_ptr<uv_connect_t> connect_req(__req);
          IOLoop * ioloop = static_cast<IOLoop* >(__req->handle->loop->data);
          try
          {
            ioloop->on_tcp_connect_cb(__req, status);
          }
          catch (...){}
        });

      if (r == 0)
      {
        req.release(); // owner transfered to UV callback
      }
      else
      {
        delete connect_req;

        req->connector->io_on_connect_exception(
          std::make_exception_ptr( std::system_error(abs(r), std::system_category()) )
          );
      }

    }
    else if (user_req->addr.empty())
    {
      create_tcp_server_socket(user_req->port, user_req->on_accept,
                               std::move(user_req->listener_err));
    }
  }

}


void IOLoop::async_send()
{
  /* ANY thread */

  // cause the IO thread to wake up
  uv_async_send( m_async.get() );
}

void IOLoop::run_loop()
{
  _INFO_("IOLoop thread starting");
  while ( true )
  {
    try
    {
      int r = uv_run(m_uv_loop, UV_RUN_DEFAULT);

      // if r == 0, there are no more handles; implies we are shutting down.
      if (r == 0) return;
    }
    catch(std::exception & e)
    {
      _ERROR_("exception in io_loop: " << e.what());
    }
    catch(...)
    {
      _ERROR_("exception in io_loop: uknown");
    }
  }
}

void IOLoop::start()
{
  m_thread = std::thread(&IOLoop::run_loop, this);
}


void IOLoop::add_server(int port,
                        std::promise<int> listen_err,
                        socket_accept_cb cb)
{
  std::unique_ptr<io_request> r( new io_request( __logptr,
                                                 port,
                                                 std::move(listen_err),
                                                 std::move(cb) ) );

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    m_pending_requests.push_back( std::move(r) );
  }

  this->async_send();
}


void IOLoop::add_passive_handle(tcp_server* myserver, IOHandle* iohandle)
{
  m_handles.push_back( iohandle );

  if (myserver->cb) myserver->cb(myserver->port, std::unique_ptr<IOHandle>(iohandle));
}


std::shared_ptr<io_connector> IOLoop::add_connection(std::string addr, int port)
{
  // create the handle, need it here, so that the caller can later request
  // cancellation
  uv_tcp_t * tcp_handle = new uv_tcp_t();
  uv_tcp_init(m_uv_loop, tcp_handle);

  std::shared_ptr<io_connector> conn ( new io_connector(m_kernel, tcp_handle) );

  std::unique_ptr<io_request> r( new io_request(__logptr ) );
  r->connector = conn;
  r->addr = addr;
  r->port = port;

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    m_pending_requests.push_back( std::move(r) );
  }

  this->async_send();

  return conn;
}




void IOLoop::request_cancel(uv_tcp_t* h, uv_close_cb cb)
{
  std::unique_ptr<io_request> r( new io_request(__logptr ) );
  r->request_type = io_request::eCancelHandle;
  r->tcp_handle = h;
  r->on_close_cb = cb;

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    m_pending_requests.push_back( std::move(r) );
  }
  this->async_send();
}



} // namespace XXX
