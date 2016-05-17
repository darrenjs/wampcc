#ifndef XXX_DEALER_SERVICE_H
#define XXX_DEALER_SERVICE_H

#include "Callbacks.h"

#include <jalson/jalson.h>

#include <memory>

namespace XXX {

  class kernel;
  class dealer_service_impl;

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

  std::shared_ptr<dealer_service_impl> m_impl;
};

} // namespace

#endif
