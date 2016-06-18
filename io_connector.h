#ifndef XXX_IO_CONNECTOR_H
#define XXX_IO_CONNECTOR_H

#include <memory>
#include <future>

#include <uv.h>

namespace XXX {

class kernel;
class IOHandle;

/* Represents the asynchronous task of creating an active socket connection */
class io_connector
{
public:
  std::future< std::unique_ptr<IOHandle> > get_future();

  // Abort the connection attempt
  void async_cancel();

private:

  void io_on_connect_success();
  void io_on_connect_exception(std::exception_ptr p);
  uv_tcp_t * get_handle() { return m_tcp_handle; }

  void request_cancel();

  io_connector(kernel&, uv_tcp_t *);

  kernel & m_kernel;
  uv_tcp_t * m_tcp_handle;
  std::promise< std::unique_ptr<IOHandle> > m_iohandle_promise;

  std::mutex m_lock;
  std::unique_ptr<std::exception_ptr> m_exception;
  enum
  {
    eInit,
    eCancelRequested,
    ePromiseSet
  } m_state;

  friend class IOLoop;
};

} // namespace XXX

#endif
