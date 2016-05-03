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
class dealer_service;
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
    int server_port = 0;
    bool enable_embed_router = false;
    std::string realm = "default_realm";
  };

  client_service(Logger*, config);
  ~client_service();

  void start();


  // /* Register a procedure.  Returns true if was added, or false if name already
  //  * existed. */
  // bool add_procedure(const std::string& uri,
  //                    const jalson::json_object& options,
  //                    rpc_cb cb,
  //                    void * data);

  // Register a procedure with a remote dealer
  t_request_id register_procedure_impl(router_conn*,
                                       const std::string& uri,
                                       const jalson::json_object& options,
                                       rpc_cb cb,
                                       void * data);
  /* Register a topic */
  void add_topic(topic*);

  /* Publish data onto a topic. The publish message will be sent to all
   * connected sessions, and optionally to the internal dealer session. */
  void publish_all(bool include_internal,
                   const std::string& topic,
                   const jalson::json_object& opts,
                   const jalson::json_array& args_list,
                   const jalson::json_object& args_dict);

  /* Used by the CALLEE to respond to a procedure call */
  void post_reply(t_invoke_id,
                  wamp_args& the_args);

  /* Used by the CALLEE to respond to a procedure call */
  void post_error(t_invoke_id,
                  std::string& error);

  // void invoke_direct(session_handle&,
  //                    t_request_id,
  //                    int,
  //                    wamp_args&);

  dealer_service * get_dealer() { return m_embed_router; }

private:

  client_service(const client_service&) = delete;
  client_service& operator=(const client_service&) = delete;

  int connect_session(router_conn&,
                      const std::string & addr,
                      int port);

  bool is_open(const router_conn*) const;

  /* Call an RPC on the peer router */
  t_request_id call_rpc(router_conn*,
                        std::string rpc,
                        const jalson::json_object& options,
                        wamp_args,
                        wamp_call_result_cb,
                        void* cb_user_data);

  // how do we find out the list of remote topics? and if we have multiple
  // sessions, then, which session has the topic we want?
  t_request_id subscribe_remote_topic(router_conn*,
                                      const std::string& uri,
                                      const jalson::json_object& options,
                                      subscription_cb cb,
                                      void * user);



  t_connection_id register_session(router_conn&);

  void handle_REGISTERED(ev_inbound_message*);
  void handle_INVOCATION(ev_inbound_message*);
  void handle_RESULT(ev_inbound_message*);
  void handle_ERROR(ev_inbound_message*);
  void handle_session_state_change(ev_session_state_event*);
  void handle_event(ev_router_session_connect_fail*);
  void handle_SUBSCRIBED(ev_inbound_subscribed*);
  void handle_EVENT(ev_inbound_message*);
  // void register_procedures();

  void new_client(IOHandle *hndl,
                  int  status,
                  t_connection_id router_session_id);

  t_request_id publish(router_conn*,
                       const std::string& uri,
                       const jalson::json_object& options,
                       wamp_args wargs);

  Logger *__logptr; /* name chosen for log macros */

  config m_config;

  // NEW approach

  struct user_procedure
  {
    std::string uri;
    rpc_cb      user_cb;
    void*       user_data;
    int         registration_id;

    user_procedure(std::string __uri,
                   rpc_cb      __user_cb,
                   void*       __user_data)
      : uri(__uri),
        user_cb(__user_cb),
        user_data(__user_data),
        registration_id(0)
    {
    }

  };

  struct procedure_map
  {
    std::map<std::string, std::shared_ptr<user_procedure> > by_uri;
    std::map<int,         std::shared_ptr<user_procedure> > by_id;
  };

  std::map<t_connection_id, procedure_map > m_procedures;

  // std::map<t_connection_id, void* > m_registered_procedures;
  // std::map< std::string, std::pair< rpc_cb,void*> > m_procedures;
  std::mutex                                        m_procedures_lock;

  // struct RegistrationKey
  // {
  //   t_connection_id router_session_id;
  //   int id; // TODO: this must be the Registration id?
  //   bool operator<(const RegistrationKey& k) const;
  // };
  //std::map <RegistrationKey, std::string>           m_registrationid_map;
  // std::mutex                                        m_registrationid_map_lock;

  // TODO: maybe later try to combine these maps, if it is obvious to tell is a
  // procedure is being invokd internally or from remote.
  //std::map <int, std::string>                       m_registrationid_map2;
  //std::mutex                                        m_registrationid_map_lock2;




  std::map<std::string, topic*> m_topics;
  std::mutex                    m_topics_lock;

  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
  std::unique_ptr<SessionMan> m_sesman;


  // TODO: rename to invocation
  struct call_context
  {
    session_handle seshandle;
    int requestid;
    // bool internal;
  };
  size_t m_callid = 0;
  std::map <size_t, call_context>  m_calls;
  std::mutex                       m_calls_lock;
  dealer_service *                 m_embed_router = nullptr;

  t_client_request_id  m_next_client_request_id;

  /* outbound rpc call requests */
  struct pending_wamp_call
  {
    std::string rpc;
    wamp_call_result_cb user_cb;
    void* user_data;
    pending_wamp_call() : user_data( nullptr ) { }
  };

  std::map<int, pending_wamp_call> m_pending_wamp_call;
  std::mutex m_pending_wamp_call_lock;

  /* Sessions to remote routers */
  std::map<t_connection_id, router_conn*> m_router_sessions;
  mutable std::mutex m_router_sessions_lock;
  t_connection_id m_next_router_session_id = 1;

  /*
    TODO: Currently have a pending map, for subscriptions.  Can try to remove
    this, but to do that,I need the Session class to allow an arbitraty object
    to be passed in, as the callback data.
   */
  struct subscription
  {
    session_handle sh;
    t_connection_id router_session_idxx;
    std::string uri;
    subscription_cb user_cb;
    void * user_data;
  };
  std::map<t_client_request_id, subscription> m_pending_wamp_subscribe;
  std::map<t_sid, std::map<size_t, subscription> > m_subscriptions;
  t_client_request_id m_subscription_req_id = 1;
  std::mutex m_subscriptions_lock;

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

  friend client_service;
};

} // namespace XXX

#endif
