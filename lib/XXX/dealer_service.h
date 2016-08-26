#ifndef XXX_DEALER_SERVICE_H
#define XXX_DEALER_SERVICE_H

#include "wamp_session.h"

#include <jalson/jalson.h>

#include <memory>
#include <future>

namespace XXX {

  class kernel;
  class pubsub_man;
  class rpc_man;
  struct rpc_details;
  class pre_session;

struct dealer_listener
{
  virtual void rpc_registered(std::string uri) = 0;
};

class dealer_service : public std::enable_shared_from_this<dealer_service>
{
public:
  dealer_service(kernel & __svc, dealer_listener*);
  ~dealer_service();

  /** Request asynchronous close */
  std::future<void> close();

  // publish to an internal topic
  void publish(const std::string& topic,
               const std::string& realm,
               const jalson::json_object& options,
               wamp_args);

  /* Asynchronously begin accepting connections on the given port. If the bind
   * and or listen fails, a non-zero error code is returned in the future. */
  std::future<int> listen(int port,
                          auth_provider auth); // TODO: needs interface argument

  void register_procedure(const std::string& realm,
                          const std::string& uri,
                          const jalson::json_object& options,
                          rpc_cb cb,
                          void * data);

private:

  void rpc_registered_cb(const rpc_details&);
  void handle_inbound_call(wamp_session*,
                           const std::string&,
                           wamp_args args,
                           wamp_invocation_reply_fn);

  void handle_session_state_change(session_handle s, bool b);

  void check_has_closed();

  dealer_service(const dealer_service&) = delete;
  dealer_service& operator=(const dealer_service&) = delete;

  kernel & m_kernel;
  logger & __logger; /* name chosen for log macros */

  std::recursive_mutex m_lock;

  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

  std::mutex m_sesions_lock;
  std::map<t_sid, std::shared_ptr<wamp_session> > m_sessions;
  std::map<t_sid, std::shared_ptr<pre_session>  > m_pre_sessions;

  std::promise< void > m_promise_on_close;

  dealer_listener* m_listener;
};

} // namespace

#endif
