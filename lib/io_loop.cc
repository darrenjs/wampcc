#include "XXX/io_loop.h"

#include "XXX/log_macros.h"
#include "XXX/kernel.h"
#include "XXX/tcp_socket.h"

#include <system_error>

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <iostream>


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
    eCancelHandle, // 1
    eCloseLoop,    // 2
    eConnect,      // 3
    eFunction      // 4
  } type;

  logger & logptr;
  std::string addr;
  std::string port;
  bool resolve_hostname;
  std::unique_ptr< std::promise<int> > listener_err;
  uv_tcp_t * tcp_handle = nullptr;
  std::function<void()> on_connect_success;
  std::function<void(std::exception_ptr)> on_connect_failure;
  std::function<void()> user_fn;
  io_request(request_type __type,
             logger & __logger)
    : type(__type),
      logptr(__logger)
  {}

  io_request(request_type __type,
             logger & __logger,
             std::string port,
             std::promise<int> p);

};


io_loop_closed::io_loop_closed()
  : std::runtime_error("io_loop closed")
{
}


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


io_request::io_request(request_type __type,
                       logger & lp,
                       std::string __port,
                       std::promise<int> listen_err)
  : type( __type),
    logptr( lp ),
    port( __port ),
    listener_err( new std::promise<int>(std::move(listen_err) ) )
{
}


io_loop::io_loop(kernel& k, std::function<void()> io_started_cb)
  : m_kernel(k),
    __logger( k.get_logger() ),
    m_uv_loop( new uv_loop_t() ),
    m_async( new uv_async_t() ),
    m_pending_requests_state(e_open)
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

  m_thread = std::thread([this, io_started_cb]() {
      m_io_thread_id = std::this_thread::get_id();
      if (io_started_cb)
        try {
          io_started_cb();
        } catch(...){ /* ignore */}
      this->io_loop::run_loop();
    });
}


// TODO: perhaps this should not be synchronous? Or rename?
void io_loop::stop()
{
  std::unique_ptr<io_request> r( new io_request( io_request::eCloseLoop,
                                                 __logger) );

  try {
    push_request(std::move(r));
  }
  catch (io_loop_closed& e)
  {
    /* ignore */
  }

  if (m_thread.joinable())
    m_thread.join();
}


io_loop::~io_loop()
{
  // uv_loop kept as raw pointer, because need to pass to several uv functions
  uv_loop_close(m_uv_loop);
  delete m_uv_loop;
}


void io_loop::on_async()
{
  /* IO thread */
  std::vector< std::unique_ptr<io_request> > work;

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    work.swap( m_pending_requests );
    if (m_pending_requests_state == e_closing)
      m_pending_requests_state = e_closed;
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
    else if (user_req->type == io_request::eConnect)
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
    else if (user_req->type == io_request::eCloseLoop)
    {
      /* close event handler run at function exit */
    }
    else if (user_req->type == io_request::eFunction)
    {
      user_req->user_fn();
    }
    else
    {
      assert(false);
    }
  }


  if (m_pending_requests_state == e_closed)
  {
    uv_close((uv_handle_t*) m_async.get(), 0);

    // While there are active handles, progress the event loop here and on
    // each iteration identify and request close any handles which have not
    // been requested to close.
    uv_walk(m_uv_loop, [](uv_handle_t* handle, void* arg) {

        if (!uv_is_closing(handle))
        {
          uv_handle_data * ptr = (uv_handle_data*) handle->data;

          if (ptr == 0)
          {
            // We are uv_walking a handle which does not have the data member
            // set. Common cause of this is a shutdown of the kernel & ioloop
            // while a wamp_connector exists which has not had its UV handle
            // used.
            uv_close(handle, [](uv_handle_t* h){
                delete h;
              });
          }
          else
          {
            assert(ptr->check() == uv_handle_data::DATA_CHECK);
            switch (ptr->type())
            {
              case uv_handle_data::e_tcp_socket:
                ptr->tcp_socket_ptr()->do_close();
                break;
            }
          }
        }
      }, nullptr);

  }

}


const std::thread::id& io_loop::get_thread_id()  const
{
  return m_io_thread_id;
}


void io_loop::run_loop()
{
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


void io_loop::connect(uv_tcp_t * handle,
                      std::string addr,
                      std::string port,
                      bool resolve_hostname,
                      std::function<void()> on_success,
                      std::function<void(std::exception_ptr)> on_failure)
{
  // create the handle, need it here, so that the caller can later request
  // cancellation

  std::unique_ptr<io_request> r( new io_request(io_request::eConnect, __logger ) );
  r->tcp_handle = handle;
  r->addr = addr;
  r->port = port;
  r->resolve_hostname = resolve_hostname;
  r->on_connect_success = on_success;
  r->on_connect_failure = on_failure;

  push_request(std::move(r));
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

    if (m_pending_requests_state == e_closed)
      throw io_loop_closed();

    if (r->type == io_request::eCloseLoop)
      m_pending_requests_state = e_closing;

    m_pending_requests.push_back( std::move(r) );
  }

  uv_async_send( m_async.get() ); // wake-up IO thread
}


void io_loop::push_fn(std::function<void()> fn)
{
  std::unique_ptr<io_request> r( new io_request( io_request::eFunction,
                                                 __logger) );
  r->user_fn = std::move(fn);
  push_request(std::move(r));
}


void version_check_libuv(int compile_major, int compile_minor)
{
  // version that our library was built against
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
