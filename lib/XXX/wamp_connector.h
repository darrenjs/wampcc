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
  std::shared_ptr<XXX::wamp_session> create_session(session_state_fn state_change_fn)
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

    XXX::rawsocket_protocol::options options;
    std::shared_ptr<XXX::wamp_session> ws (
      XXX::wamp_session::create<XXX::rawsocket_protocol>(*m_kernel,
                                                         std::move(socket),
                                                         std::move(state_change_fn),
                                                         options)
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

private:

  wamp_connector(kernel* k, t_on_complete_fn fn);

  wamp_connector(const wamp_connector&) = delete;
  wamp_connector& operator=(const wamp_connector&) = delete;

  std::unique_ptr<io_handle> create_handle();

  kernel* m_kernel;

  t_on_complete_fn m_on_complete_fn;

  std::mutex m_mutex;
  uv_tcp_t * m_connect_handle;

  std::promise<void> m_result_promise;
  std::future<void>  m_result_fut;
};

} // namespace XXX

#endif
