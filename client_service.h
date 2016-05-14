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

class IOHandle;
class IOLoop;
class Logger;
class Session;
class SessionMan;
class client_service;
class event_loop;
class ev_inbound_message;
class topic;
// class dealer_service;
class ev_inbound_subscribed;
class ev_session_state_event;
class ev_router_session_connect_fail;


class router_conn;

/*
  Combine the Callee and Caller interfaces.
 */
class client_service
{
public:

  struct config
  {
    // int server_port = 0;
    // bool enable_embed_router = false;
    std::string realm = "default_realm";
  };

  client_service(Logger*, config);
  ~client_service();

  void start();

  /* Register a topic */
  void add_topic(topic*);

private:

  client_service(const client_service&) = delete;
  client_service& operator=(const client_service&) = delete;

  int connect_session(router_conn&,
                      const std::string & addr,
                      int port);


  t_connection_id register_session(router_conn&);

  void handle_session_state_change(ev_session_state_event*);
  void handle_event(ev_router_session_connect_fail*);

  void new_client(IOHandle *hndl,
                  int  status,
                  t_connection_id router_session_id);

  Logger *__logptr; /* name chosen for log macros */

  config m_config;

public:
  Logger * get_logger();
  IOLoop* get_ioloop();
  event_loop* get_event_loop();
  SessionMan* get_session_man();

  std::map<std::string, topic*> m_topics;
  std::mutex                    m_topics_lock;

  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
  std::unique_ptr<SessionMan> m_sesman;


  t_client_request_id  m_next_client_request_id;

  /* Sessions to remote routers */
  std::map<t_connection_id, router_conn*> m_router_sessions;
  mutable std::mutex m_router_sessions_lock;
  t_connection_id m_next_router_session_id = 1;

  friend class router_conn;
};


class router_conn
{
public:
  void * user;

  router_conn(client_service * __svc,
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

  int router_session_id() const { return m_router_session_id;}

  client_service * service() { return m_svc; }

  session_handle handle() { return m_internal_session_handle; }

private:

  client_service * m_svc;
  router_session_connect_cb m_connection_cb;
  t_connection_id m_router_session_id;

  session_handle m_internal_session_handle;
  std::shared_ptr<Session> m_session;
  // struct user_procedure
  // {
  //   std::string uri;
  //   rpc_cb      user_cb;
  //   void*       user_data;
  //   int         registration_id;

  //   user_procedure(std::string __uri,
  //                  rpc_cb      __user_cb,
  //                  void*       __user_data)
  //     : uri(__uri),
  //       user_cb(__user_cb),
  //       user_data(__user_data),
  //       registration_id(0)
  //   {
  //   }

  // };

  // struct procedure_map
  // {
  //   std::map<std::string, std::shared_ptr<user_procedure> > by_uri;
  //   std::map<int,         std::shared_ptr<user_procedure> > by_id;
  // }  m_procedures;
  // std::mutex                                m_procedures_lock;

  friend client_service;
};

} // namespace XXX

#endif
