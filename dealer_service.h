#ifndef XXX_DEALER_SERVICE_H
#define XXX_DEALER_SERVICE_H


#include "Callbacks.h"
#include "Session.h"

#include <jalson/jalson.h>

#include <list>
#include <memory>
#include <mutex>

namespace XXX {

  class kernel;
  class SessionMan;
  class pubsub_man;
  class rpc_man;
  class Logger;
  struct rpc_details;
  class event;


struct dealer_listener
{
  virtual void rpc_registered(std::string uri) = 0;
};

class dealer_service
{
public:
  dealer_service(kernel & __svc, dealer_listener*);
  ~dealer_service();

  // publish to an internal topic
  t_request_id publish(const std::string& topic,
                       const std::string& realm,
                       const jalson::json_object& options,
                       wamp_args);

  void listen(int port);// TODO: needs interface argument

  void register_procedure(const std::string& realm,
                          const std::string& uri,
                          const jalson::json_object& options,
                          rpc_cb cb,
                          void * data);

private:
  dealer_service(const dealer_service&) = delete;
  dealer_service& operator=(const dealer_service&) = delete;

  void rpc_registered_cb(const rpc_details&);

  void handle_inbound_call(Session*,
                           const std::string&,
                           wamp_args args,
                           wamp_invocation_reply_fn);

  // essential components
  Logger *__logptr; /* name chosen for log macros */
  kernel & m_kernel;

  std::unique_ptr<SessionMan> m_sesman;
  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

  dealer_listener* m_listener;
};

} // namespace

#endif
