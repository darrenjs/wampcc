#ifndef XXX_WAMP_CONNECTOR_H
#define XXX_WAMP_CONNECTOR_H

#include "XXX/io_loop.h"
#include "XXX/io_handle.h"
#include "XXX/kernel.h"
#include "XXX/wamp_session.h"
#include "XXX/rawsocket_protocol.h"

#include <memory>
#include <mutex>
#include <string>

struct uv_tcp_s;
typedef struct uv_tcp_s uv_tcp_t;

namespace XXX {


class wamp_connector
{
  public:

  static std::shared_ptr<wamp_connector> create(kernel* k,
                                                std::string addr,
                                                std::string port,
                                                bool resolve_hostname,
                                                session_state_fn fn)
  {
    version_check_libuv(UV_VERSION_MAJOR, UV_VERSION_MINOR);

    std::shared_ptr<wamp_connector> sp( new wamp_connector(k, std::move(fn)) );

    std::weak_ptr<wamp_connector> wp (sp);

    auto success_fn = [wp]() {
      if (auto sp = wp.lock())
        sp->on_success();
    };
    auto failure_fn = [wp](std::exception_ptr e) {
      if (auto sp = wp.lock())
        sp->on_failure(std::move(e));
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

  std::future< std::shared_ptr<wamp_session> > get_future()
  {
    return this->m_promise.get_future();
  }

  ~wamp_connector()
  {
    std::unique_lock<std::mutex> guard(m_mutex);
    if (this->m_connect_handle)
      this->m_kernel->get_io()->cancel_connect(m_connect_handle);
  }

private:

  void on_success()
  {
    std::unique_lock<std::mutex> guard(m_mutex);

    std::unique_ptr<io_handle> socket (
      new io_handle( *m_kernel,
                     (uv_stream_t *) m_connect_handle,
                     m_kernel->get_io() ) );
    m_connect_handle = nullptr;

    XXX::rawsocket_protocol::options options;
    std::shared_ptr<XXX::wamp_session> ws (
      XXX::wamp_session::create<XXX::rawsocket_protocol>(*m_kernel,
                                                         std::move(socket),
                                                         std::move(m_state_change_fn),
                                                         options)
      );

    m_promise.set_value( ws );
  }

  void on_failure(std::exception_ptr e)
  {
    std::unique_lock<std::mutex> guard(m_mutex);
    m_promise.set_exception(std::move(e));
  }


  wamp_connector(kernel* k,
                 session_state_fn fn)
  : m_kernel(k),
    m_connect_handle(nullptr),
    m_state_change_fn(fn)
  {
  }

  wamp_connector(const wamp_connector&) = delete;
  wamp_connector& operator=(const wamp_connector&) = delete;

  kernel* m_kernel;

  std::promise< std::shared_ptr<wamp_session> > m_promise;

  std::mutex m_mutex;
  uv_tcp_t * m_connect_handle;

  session_state_fn  m_state_change_fn;
};

} // namespace XXX

#endif
