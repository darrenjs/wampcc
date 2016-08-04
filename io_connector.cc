#include "io_connector.h"

#include "kernel.h"
#include "IOHandle.h"
#include "IOLoop.h"

namespace XXX {


io_connector::io_connector(kernel& k, uv_tcp_t * h)
  : m_kernel(k),
    m_tcp_handle(h),
    m_state(eInit)
{
}


void io_connector::async_cancel()
{
  std::unique_lock<std::mutex> guard( m_lock );
  if (m_state == io_connector::eInit) request_cancel();
}


std::future< std::unique_ptr<IOHandle> > io_connector::get_future()
{
  return m_iohandle_promise.get_future();
}


void io_connector::io_on_connect_success()
{
  /* IO thread */

  std::unique_lock<std::mutex> guard( m_lock );

  if (m_state == eInit)
  {
    m_state = io_connector::ePromiseSet;

    std::unique_ptr< IOHandle > hndl (
      new IOHandle( m_kernel,
                    (uv_stream_t *) m_tcp_handle,
                    m_kernel.get_io() ) );

    m_iohandle_promise.set_value( std::move(hndl) );
  }
  else if (m_state == eCancelRequested)
  {
    // Dont create IOHandle, because the actual tcp handle is in the process
    // of closing. The promise will be set when the uv_close callback is
    // triggered.
  }
}


void io_connector::io_on_connect_exception(std::exception_ptr p)
{
    /* IO thread */

  std::unique_lock<std::mutex> guard( m_lock );

  m_exception.reset( new std::exception_ptr(std::move(p)) );

  if (m_state == io_connector::eInit) request_cancel();
}


void io_connector::request_cancel()
{
  m_state = io_connector::eCancelRequested;
  m_tcp_handle->data = this;

  m_kernel.get_io()->request_cancel(
    m_tcp_handle,
    [](uv_handle_t* handle)
    {
      /* IO thread */
      io_connector* self = (io_connector*) handle->data;

      std::unique_lock<std::mutex> guard(self->m_lock );
      self->m_state = io_connector::ePromiseSet;

      if (self->m_exception)
        self->m_iohandle_promise.set_exception( *self->m_exception.get() );
      else
        self->m_iohandle_promise.set_value(0);

      delete self->m_tcp_handle;
    });
}


} // namespace XXX
