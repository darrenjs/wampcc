#include <XXX/wamp_connector.h>

#include "XXX/event_loop.h"

namespace XXX
{

  wamp_connector::wamp_connector(kernel* k, t_on_complete_fn fn,
                                 std::string addr,
                                 std::string port)
  : m_kernel(k),
    m_host(addr),
    m_port(port),
    m_on_complete_fn(fn),
    m_connect_handle(nullptr),
    m_result_fut(m_result_promise.get_future())
  {
  }


  wamp_connector::~wamp_connector()
  {
    std::unique_lock<std::mutex> guard(m_mutex);
    if (m_connect_handle)
      m_kernel->get_io()->cancel_connect(m_connect_handle);
  }


  std::shared_ptr<wamp_connector> wamp_connector::create(kernel* k,
                                                         std::string addr,
                                                         std::string port,
                                                         bool resolve_hostname,
                                                         t_on_complete_fn fn)
  {
    std::shared_ptr<wamp_connector> sp( new wamp_connector(k, fn, addr, port));

    auto success_fn = [sp]() {

      sp->m_result_promise.set_value();
      if (sp->m_on_complete_fn)
        sp->m_kernel->get_event_loop()->dispatch([sp](){sp->m_on_complete_fn(sp);});

    };

    auto failure_fn = [sp](std::exception_ptr e) {

      sp->m_result_promise.set_exception(std::move(e));
      if (sp->m_on_complete_fn)
        sp->m_kernel->get_event_loop()->dispatch([sp](){sp->m_on_complete_fn(sp);});

    };

    {
      std::unique_lock<std::mutex> guard(sp->m_mutex);
      sp->m_connect_handle = k->get_io()->connect(addr,port,
                                                  resolve_hostname,
                                                  success_fn,
                                                  failure_fn);
    }

    return sp;
  }

  std::unique_ptr<io_handle> wamp_connector::create_handle()
  {
    std::unique_ptr<io_handle> socket (
      new io_handle( *m_kernel,
                     (uv_stream_t *) m_connect_handle,
                     m_kernel->get_io() ) );

    return socket;
  }


  bool wamp_connector::attempt_cancel()
  {
    std::unique_lock<std::mutex> guard(m_mutex);
    if (m_connect_handle)
    {
      m_kernel->get_io()->cancel_connect(m_connect_handle);
      m_connect_handle = nullptr;
      return true;
    }
    else
      return false;
  }


}
