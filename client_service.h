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
class inbound_message_event;
class topic;
class dealer_service;
class ev_inbound_subscribed;
class session_state_event;
class ev_router_session_connect_fail;

/*
  Combine the Callee and Caller interfaces.
 */
class client_service
{
public:

  struct config
  {
    int port = 0;
    std::string remote_addr;
    int remote_port = 0;
    bool enable_embed_router = false;
  };

  client_service(Logger*, config);
  ~client_service();

  void start();

  // create a new session, returning either the assigned session ID, or zero if
  // the session could not be created
  t_rsid create_session(const std::string & addr,
                        int port,
                        tcp_connect_attempt_cb user_cb,
                        void* user_data);

  void session_attempt_connect(t_rsid router_session_id);

  bool is_open(t_rsid router_session_id) const;

  /* Call an RPC on the peer router */
  t_client_request_id call_rpc(t_rsid router_session_id,
                               std::string rpc,
                               rpc_args,
                               call_user_cb,
                               void* cb_user_data);


  /* Register a procedure.  Returns true if was added, or false if name already
   * existed. */
  bool add_procedure(const std::string& uri,
                     rpc_cb cb,
                     void * data);

  /* Used by the CALLEE to respond to a procedure call */
  void post_reply(t_invoke_id,
                  rpc_args& the_args);

  /* Used by the CALLEE to respond to a procedure call */
  void post_error(t_invoke_id,
                  std::string& error);

  void add_topic(topic*);


  // how do we find out the list of remote topics? and if we have multiple
  // sessions, then, which session has the topic we want?
  void subscribe_remote_topic(t_rsid router_session_id,
                              const std::string& uri,
                              subscription_cb cb,
                              void * user);

  void invoke_direct(session_handle&,
                     t_request_id,
                     int,
                     rpc_args&);



private:

  client_service(const client_service&) = delete;
  client_service& operator=(const client_service&) = delete;

  void handle_REGISTERED(inbound_message_event*);
  void handle_INVOCATION(inbound_message_event*);
  void handle_RESULT(inbound_message_event*);
  void handle_ERROR(inbound_message_event*);
  void handle_session_state_change(session_state_event*);
  void handle_event(ev_router_session_connect_fail*);
  void handle_SUBSCRIBED(ev_inbound_subscribed*);
  void handle_EVENT(inbound_message_event*);
  void register_procedures();

  void new_client(IOHandle *hndl,
                  int  status,
                  t_rsid router_session_id);

  Logger *__logptr; /* name chosen for log macros */

  config m_config;

  std::map< std::string, std::pair< rpc_cb,void*> > m_procedures;
  std::mutex                                        m_procedures_lock;

  struct RegistrationKey
  {
    unsigned int s;
    int id;
    bool operator<(const RegistrationKey& k) const;
  };
  std::map <RegistrationKey, std::string>           m_registrationid_map;
  std::mutex                                        m_registrationid_map_lock;

  // TODO: maybe later try to combine these maps, if it is obvious to tell is a
  // procedure is being invokd internally or from remote.
  std::map <int, std::string>                       m_registrationid_map2;
  std::mutex                                        m_registrationid_map_lock2;

  std::map<std::string, topic*> m_topics;
  std::mutex                    m_topics_lock;

  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
  std::unique_ptr<SessionMan> m_sesman;


  struct call_context
  {
    session_handle seshandle;
    int requestid;
    bool internal;
  };
  size_t m_callid = 0;
  std::map <size_t, call_context>  m_calls;
  std::mutex                       m_calls_lock;
  dealer_service *                 m_embed_router = nullptr;

  t_client_request_id  m_next_client_request_id;

  // TODO: move to impl
  struct pending_request
  {
    call_user_cb cb;
    std::string rpc; // TODO: standardise the varname for rpc name
    void* user_cb_data;

    pending_request() : user_cb_data( nullptr ) { }
  };

  std::map<int, pending_request> m_pending_requests;
  std::mutex m_pending_requests_lock;


  struct router_session
  {
    std::string addr;
    int         port;
    void*       user;
    tcp_connect_attempt_cb user_cb;
    session_handle sh;

    router_session();
    router_session(const std::string & addr,
                   int port,
                   void* user_data);
  };

  std::map<t_rsid, router_session> m_router_sessions;
  mutable std::mutex m_router_sessions_lock;
  t_rsid m_next_router_id = 1;

  /*
    TODO: Currently have a pending map, for subscriptions.  Can try to remove
    this, but to do that,I need the Session class to allow an arbitraty object
    to be passed in, as the callback data.
   */
  struct subscription
  {
    session_handle sh;
    std::string uri;
    subscription_cb user_cb;
    void * user_data;
  };
  std::map<std::string, subscription> m_subscriptions;
  std::map<t_client_request_id, subscription> m_pending_subscription;
  t_client_request_id m_subscription_req_id = 1;
  std::mutex m_subscriptions_lock;

  std::map<t_sid, std::map<size_t, subscription> > m_subscriptions2;


  // new style -- is this even this correct place
  std::map<t_sid, std::map<size_t, subscription*> > m_active_subs;



};

} // namespace XXX

#endif
