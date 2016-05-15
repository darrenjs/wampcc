#ifndef XXX_CLIENT_SERVICE_H
#define XXX_CLIENT_SERVICE_H

#include "Callbacks.h"

#include <jalson/jalson.h>

#include <memory>
#include <string>


namespace XXX {

class kernel;

struct router_conn_impl;
class router_conn
{
public:
  void * user;

  router_conn(kernel * __svc,
              std::string realm,
              router_session_connect_cb,
              void * __user = nullptr);
  ~router_conn();
  router_conn(const router_conn&) = delete;
  router_conn& operator=(const router_conn&) = delete;

  int connect(const std::string & addr, int port);

  // Register a procedure with a remote dealer
  t_request_id provide(const std::string& uri,
                       const jalson::json_object& options,
                       rpc_cb cb,
                       void * data);

  t_request_id call(std::string rpc,
                    const jalson::json_object& options,
                    wamp_args,
                    wamp_call_result_cb,
                    void* user);

  t_request_id subscribe(const std::string& uri,
                         const jalson::json_object& options,
                         subscription_cb cb,
                         void * user);

  t_request_id publish(const std::string& uri,
                       const jalson::json_object& options,
                       wamp_args);

private:

  std::shared_ptr<router_conn_impl> m_impl;

};

} // namespace XXX

#endif
