#include "XXX/io_loop.h"

#include "XXX/log_macros.h"
#include "XXX/io_handle.h"
#include "XXX/kernel.h"

#include <system_error>

#include <unistd.h>
#include <string.h>


static const char* safe_str(const char* s)
{
  return s? s : "null";
}

namespace XXX {

struct io_request
{
  enum request_type
  {
    eNone = 0,
    eCancelHandle,
    eAddServer,
    eAddConnection,
    eCloseLoop
  } type;

  logger & logptr;
  std::string addr;
  std::string port;
  bool resolve_hostname;
  std::unique_ptr< std::promise<int> > listener_err;
  uv_tcp_t * tcp_handle = nullptr;
  socket_accept_cb on_accept;

  std::function<void()> on_connect_success;
  std::function<void(std::exception_ptr)> on_connect_failure;

  io_request(request_type __type,
             logger & __logger)
    : type(__type),
      logptr(__logger)
  {}

  io_request(request_type __type,
             logger & __logger,
             std::string port,
             std::promise<int> p,
             socket_accept_cb );

};



void io_loop::on_tcp_connect_cb(uv_connect_t* connect_req, int status)
{
  /* IO thread */

  std::unique_ptr<io_request> ioreq ((io_request*) connect_req->data );

  if (status < 0)
  {
    std::ostringstream oss;
    oss << "uv_connect: " << status << ", " << safe_str(uv_err_name(status))
        << ", " << safe_str(uv_strerror(status));
    ioreq->on_connect_failure(
      std::make_exception_ptr( std::runtime_error(oss.str()) )
      );
  }
  else
  {
    ioreq->on_connect_success();
  }
}


static void __on_tcp_connect(uv_stream_t* server, int status)
{
  // io_loop has set itself as the uv_loop data member
  tcp_server* myserver = (tcp_server*) server;
  io_loop * myio_loop = static_cast<io_loop* >(server->loop->data);

  logger & __logger = myio_loop->get_logger();

  // TODO: review if this is correct error handling
  if (status < 0)
  {
    LOG_ERROR("New connection error " <<  uv_strerror(status));
    return;
  }

  uv_tcp_t *client = new uv_tcp_t();
  uv_tcp_init(myio_loop->uv_loop(), client);

  if (uv_accept(server, (uv_stream_t *) client) == 0)
  {
    io_handle* ioh = new io_handle( myio_loop->get_kernel(),
                                  (uv_stream_t *) client, myio_loop);

    // register the stream before beginning read operations (which happens once
    // a protocol object has been constructed)
    myserver->ioloop->add_passive_handle(myserver, ioh );
  }
  else
  {
    uv_close((uv_handle_t *) client, NULL);
  }

}


io_request::io_request(request_type __type,
                       logger & lp,
                       std::string __port,
                       std::promise<int> listen_err,
                       socket_accept_cb __on_accept)
  : type( __type),
    logptr( lp ),
    port( __port ),
    listener_err( new std::promise<int>(std::move(listen_err) ) ),
    on_accept( std::move(__on_accept) )
{
}


io_loop::io_loop(kernel& k)
  :  m_kernel(k),
     __logger( k.get_logger() ),
    m_uv_loop( new uv_loop_t() ),

    m_async( new uv_async_t() ),
    m_pending_flags( eNone )
{
  version_check_libuv(UV_VERSION_MAJOR, UV_VERSION_MINOR);

  uv_loop_init(m_uv_loop);
  m_uv_loop->data = this;

  // set up the async handler
  uv_async_init(m_uv_loop, m_async.get(), [](uv_async_t* h) {
      io_loop* p = static_cast<io_loop*>( h->data );
      p->on_async();
    });
  m_async->data = this;

  // TODO: I prefer to not have to do this.  Need to review what is the correct
  // policy for handling sigpipe using libuv.
  //  signal(SIGPIPE, SIG_IGN);
}


void io_loop::stop()
{
  std::unique_ptr<io_request> r( new io_request( io_request::eCloseLoop,
                                                 __logger) );
  push_request(std::move(r));

  if (m_thread.joinable()) m_thread.join();
}


io_loop::~io_loop()
{
  // uv_loop kept as raw pointer, because need to pass to several uv functions
  uv_loop_close(m_uv_loop);
  delete m_uv_loop;
}


void io_loop::create_tcp_server_socket(int port,
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


void io_loop::on_async()
{
  /* IO thread */
  std::vector< std::unique_ptr<io_request> > work;
  int pending_flags = eNone;

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    work.swap( m_pending_requests );
    std::swap(pending_flags, m_pending_flags);
  }

  for (auto & user_req : work)
  {
    if (user_req->type == io_request::eCancelHandle)
    {
      auto handle_to_cancel = (uv_handle_t*) user_req->tcp_handle;
      if (!uv_is_closing(handle_to_cancel))
        uv_close(handle_to_cancel, [](uv_handle_t* handle) {
            delete handle;
          });
    }
    else if (user_req->type == io_request::eAddConnection)
    {
      std::unique_ptr<io_request> req( std::move(user_req) );

      const struct sockaddr* addrptr;
      struct sockaddr_in inetaddr;
      memset(&inetaddr, 0, sizeof(inetaddr));

      int r = 0;
      uv_getaddrinfo_t resolver;
      memset(&resolver, 0, sizeof(resolver));

      if (req->resolve_hostname)
      {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = 0;

        r = uv_getaddrinfo(m_uv_loop, &resolver, nullptr,
                            req->addr.c_str(), req->port.c_str(),
                           &hints);

        if (r<0)
        {
          // address resolution failed, to set an error on the promise
          std::ostringstream oss;
          oss << "uv_getaddrinfo: " << r << ", " << safe_str(uv_err_name(r))
              << ", " << safe_str(uv_strerror(r));
          req->on_connect_failure(
            std::make_exception_ptr( std::runtime_error(oss.str()) )
            );
          return;
        }

        addrptr = resolver.addrinfo->ai_addr;
      }
      else
      {
        // use inet_pton functions
        uv_ip4_addr(req->addr.c_str(), atoi(req->port.c_str()), &inetaddr);
        addrptr = (const struct sockaddr*) &inetaddr;
      }

      std::unique_ptr<uv_connect_t> connect_req ( new uv_connect_t() );
      connect_req->data = (void*) req.get();

      LOG_INFO("making new tcp connection to " << req->addr.c_str() <<  ":" << req->port);

      r = uv_tcp_connect(
        connect_req.get(),
        req->tcp_handle,
        addrptr,
        [](uv_connect_t* __req, int status)
        {
          std::unique_ptr<uv_connect_t> connect_req(__req);
          io_loop * ioloop = static_cast<io_loop* >(__req->handle->loop->data);
          try
          {
            ioloop->on_tcp_connect_cb(__req, status);
          }
          catch (...){}
        });

      if (r == 0)
      {
        // resource  ownership transfered to UV callback
        req.release();
        connect_req.release();
      }
      else
      {
        std::ostringstream oss;
        oss << "uv_tcp_connect: " << r << ", " << safe_str(uv_err_name(r))
            << ", " << safe_str(uv_strerror(r));
        req->on_connect_failure(
          std::make_exception_ptr( std::runtime_error(oss.str()) )
          );
      }
    }
    else if (user_req->type == io_request::eAddServer)
    {
      create_tcp_server_socket(atoi(user_req->port.c_str()),
                               user_req->on_accept,
                               std::move(user_req->listener_err));
    }
    else if (user_req->type == io_request::eCloseLoop)
    {
      for (auto & i : m_server_handles)
        uv_close((uv_handle_t*)i.get(), 0);

      uv_close((uv_handle_t*) m_async.get(), 0);

      // While there are active handles, progress the event loop here and on
      // each iteration identify and request close any handles which have not
      // been requested to close.
      uv_walk(m_uv_loop, [](uv_handle_t* handle, void* arg){
          if (!uv_is_closing(handle))
          {
            uv_close(handle, [](uv_handle_t* handle){
                delete handle;
              });
          }
        }, nullptr);

      if (uv_run(m_uv_loop, UV_RUN_NOWAIT) != 0)
        LOG_WARN("expected uv_run to return 0 after handle closing");

      return; // don't process any more items in queue (should be none)
    }
  }

}


void io_loop::run_loop()
{
  LOG_INFO("io_loop thread starting");
  while ( true )
  {
    try
    {
      int r = uv_run(m_uv_loop, UV_RUN_DEFAULT);

      if (r == 0) /*  no more handles; we are shutting down */
        return;
    }
    catch(std::exception & e)
    {
      LOG_ERROR("exception in io_loop: " << e.what());
    }
    catch(...)
    {
      LOG_ERROR("uknown exception in io_loop");
    }
  }
}


void io_loop::start()
{
  m_thread = std::thread(&io_loop::run_loop, this);
}


void io_loop::add_server(int port,
                        std::promise<int> listen_err,
                        socket_accept_cb cb)
{
  std::ostringstream oss;
  oss << port;

  std::unique_ptr<io_request> r( new io_request( io_request::eAddServer,
                                                 __logger,
                                                 oss.str(),
                                                 std::move(listen_err),
                                                 std::move(cb) ) );

  push_request(std::move(r));
}


void io_loop::add_passive_handle(tcp_server* myserver, io_handle* iohandle)
{
  if (myserver->cb) myserver->cb(myserver->port, std::unique_ptr<io_handle>(iohandle));
}


uv_tcp_t* io_loop::connect(std::string addr,
                           std::string port,
                           bool resolve_hostname,
                           std::function<void()> on_success,
                           std::function<void(std::exception_ptr)> on_failure)
{
  // create the handle, need it here, so that the caller can later request
  // cancellation
  uv_tcp_t * tcp_handle = new uv_tcp_t();
  uv_tcp_init(m_uv_loop, tcp_handle);

  std::unique_ptr<io_request> r( new io_request(io_request::eAddConnection, __logger ) );
  r->tcp_handle = tcp_handle;
  r->addr = addr;
  r->port = port;
  r->resolve_hostname = resolve_hostname;
  r->on_connect_success = on_success;
  r->on_connect_failure = on_failure;

  push_request(std::move(r));

  return tcp_handle;
}


void io_loop::cancel_connect(uv_tcp_t * handle)
{
  std::unique_ptr<io_request> r( new io_request(io_request::eCancelHandle, __logger ) );
  r->tcp_handle = handle;
  push_request(std::move(r));
}


void io_loop::push_request(std::unique_ptr<io_request> r)
{
  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    m_pending_requests.push_back( std::move(r) );
  }

  uv_async_send( m_async.get() ); // wake-up IO thread
}


void version_check_libuv(int compile_major, int compile_minor)
{
  // version that our library was build against
  int library_major = UV_VERSION_MAJOR;
  int library_minor = UV_VERSION_MINOR;

  // version we are linked to at runtime
  int runtime_major = (uv_version() & 0xFF0000) >> 16;
  int runtime_minor = (uv_version() & 0x00FF00) >> 8;

  // check all versions are consistent
  if ( compile_major != library_major || compile_major != runtime_major ||
       compile_minor != library_minor || compile_minor != runtime_minor)
  {
    std::ostringstream oss;
    oss << "libuv version mismatch; "
        << "user-compile-time: " << compile_major  << "." << compile_minor
        << ", library-compile-time: " << library_major  << "." << library_minor
        << ", link-time: " << runtime_major << "." << runtime_minor;
    throw std::runtime_error( oss.str() );
  }
}

} // namespace XXX
