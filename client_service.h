#ifndef XXX_CLIENT_SERVICE_H
#define XXX_CLIENT_SERVICE_H

#include "Callbacks.h"
#include "wamp_session.h"

#include <jalson/jalson.h>

#include <memory>
#include <string>
#include <future>


namespace XXX {

class kernel;
class IOHandle;
struct router_conn_impl;

class router_conn
{
public:
  void * user;

  router_conn(kernel * __svc,
              client_credentials cc,
              router_session_connect_cb,
              std::unique_ptr<IOHandle> up_handle,
              void * __user);
  ~router_conn();
  router_conn(const router_conn&) = delete;
  router_conn& operator=(const router_conn&) = delete;


  /* request close */
  std::shared_future<void> close();

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
