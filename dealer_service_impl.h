#ifndef XXX_DEALER_SERVICE_IMPL_H
#define XXX_DEALER_SERVICE_IMPL_H

#include "Callbacks.h"
#include "wamp_session.h"

#include <memory>

namespace XXX {

  class kernel;
  class SessionMan;
  class pubsub_man;
  class rpc_man;
  class Logger;
  struct dealer_listener;
  struct rpc_details;


class dealer_service_impl : public std::enable_shared_from_this<dealer_service_impl>
{
public:
  dealer_service_impl(kernel & __svc, dealer_listener* l);
  ~dealer_service_impl();

  dealer_service_impl(const dealer_service_impl&) = delete;
  dealer_service_impl& operator=(const dealer_service_impl&) = delete;

  // publish to an internal topic
  void publish(const std::string& topic,
               const std::string& realm,
               const jalson::json_object& options,
               wamp_args);

  void register_procedure(const std::string& realm,
                          const std::string& uri,
                          const jalson::json_object& options,
                          rpc_cb cb,
                          void * data);

  void listen(int port);

  void disown();

private:

  void rpc_registered_cb(const rpc_details&);
  void handle_inbound_call(wamp_session*,
                           const std::string&,
                           wamp_args args,
                           wamp_invocation_reply_fn);


  // essential components
  Logger *__logptr; /* name chosen for log macros */
  kernel & m_kernel;

  std::recursive_mutex m_lock;

  std::unique_ptr<SessionMan> m_sesman;
  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

  dealer_listener* m_listener;
};

} // namespace XXX

#endif
