#ifndef XXX_WAMP_CONNECTOR_H
#define XXX_WAMP_CONNECTOR_H

#include "XXX/io_handle.h"
#include "XXX/io_loop.h"
#include "XXX/kernel.h"
#include "XXX/wamp_session.h"
#include "XXX/rawsocket_protocol.h"

#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>


struct uv_tcp_s;
typedef struct uv_tcp_s uv_tcp_t;

namespace XXX {

class wamp_connector
{
public:

  typedef std::function<void(std::shared_ptr<wamp_connector>)> t_on_complete_fn;

  static std::shared_ptr<wamp_connector> create(kernel* k,
                                                std::string addr,
                                                std::string port,
                                                bool resolve_hostname,
                                                t_on_complete_fn fn = nullptr);

  std::future<void> & completion_future() { return m_result_fut;  }

   /** Return the session, or, throw an excption.  Should only be called once */
  template <typename T>
  std::shared_ptr<wamp_session> create_session(session_state_fn state_change_fn,
                                               typename T::options protocol_opts={})
  {
    std::unique_lock<std::mutex> guard(m_mutex);

    // A common source of subtle error is to accidentally include a user copy of
    // libuv into this header. This check is to detect that.
    version_check_libuv(UV_VERSION_MAJOR, UV_VERSION_MINOR);

    m_result_fut.get();

    if (m_connect_handle == nullptr)
      throw std::runtime_error("wamp connect request cancelled");

    std::unique_ptr<io_handle> socket = this->create_handle();
    m_connect_handle = nullptr;

    protocol_opts.connect_host = m_host;

    std::shared_ptr<wamp_session> ws (
      wamp_session::create<T>(*m_kernel,
                              std::move(socket),
                              std::move(state_change_fn),
                              protocol_opts)
      );

    return ws;
  }

  /** Attempt to cancel a pending wamp connect request.  This might fail if the
   * IO operation completes in another thread before this function has acquired
   * exclusive access to the handle (in which case a session can be created via
   * the create() method). Returns true if cancel succeeded, or false if
   * failed. */
  bool attempt_cancel();

  ~wamp_connector();

  const std::string& host() const { return m_host;  }
  const std::string& port() const { return  m_port; }

private:

  wamp_connector(kernel* k, t_on_complete_fn fn, std::string host, std::string port);

  wamp_connector(const wamp_connector&) = delete;
  wamp_connector& operator=(const wamp_connector&) = delete;

  std::unique_ptr<io_handle> create_handle();

  kernel* m_kernel;

  std::string m_host;
  std::string m_port;

  t_on_complete_fn m_on_complete_fn;

  std::mutex m_mutex;
  uv_tcp_t * m_connect_handle;

  std::promise<void> m_result_promise;
  std::future<void>  m_result_fut;
};

} // namespace XXX

#endif
