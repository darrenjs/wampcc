#ifndef XXX_CLIENT_SERVICE_H
#define XXX_CLIENT_SERVICE_H

#include "Callbacks.h"

#include <jalson/jalson.h>

#include <functional>
#include <map>
#include <string>
#include <mutex>
#include <memory>
#include <ostream>
#include <string>


namespace XXX {

class IOLoop;
class Logger;
class Session;
class event_loop;
class topic;

/*
  Combine the Callee and Caller interfaces.
 */
class client_service
{
public:

  client_service(Logger*);
  ~client_service();

  void start();

  // /* Register a topic */
  // void add_topic(topic*);

  Logger * get_logger();
  IOLoop* get_io();
  event_loop* get_event_loop();

  // std::map<std::string, topic*> m_topics;
  // std::mutex                    m_topics_lock;


private:
  client_service(const client_service&) = delete;
  client_service& operator=(const client_service&) = delete;

  Logger *__logptr; /* name chosen for log macros */
  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
};


class router_conn
{
public:
  void * user;

  router_conn(client_service * __svc,
              std::string realm,
              router_session_connect_cb,
              void * __user = nullptr);

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

  client_service * service() { return m_svc; }

private:

  client_service * m_svc;
  Logger *__logptr; /* name chosen for log macros */

  std::string m_realm;
  router_session_connect_cb m_user_cb;

  std::shared_ptr<Session> m_session;
};

} // namespace XXX

#endif
