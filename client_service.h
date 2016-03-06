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




class router_session
{
public:
  std::string addr;
  int         port;
  void*       user;

  router_session(const std::string & addr,
                 int port,
                 void* user_data);

private:
};
/*
  Combine the Callee and Caller interfaces

  Used for external and internal service

  Note sure how to design this; will just try to evolve it

  Ideally want to use this for following scenarios:

  - an application which serves as a Dealer but also has internal procedures

  - an admin-style application, which wants to make Calls to a remote dealer

  - an endpoint application which registers RPCs

  - can we have a hybrid? ie., I expose a socket and can either register my
    procuedures to an external dealer, or, can handle calls/invokes myself?
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

  // TODO: the whole connector business shoudl be in a separate object
  void connect(const std::string & addr,
               int port,
               tcp_connect_attempt_cb user_cb,
               void* user_data);

  // TODO: the whole connector business shoudl be in a separate object
  router_session* connect_to_router(const std::string & addr,
                                    int port,
                                    tcp_connect_attempt_cb user_cb,
                                    void* user_data);

  /* Call an RPC on the peer router */
  t_client_request_id call_rpc(session_handle& sh,
                               std::string rpc,
                               call_user_cb,
                               rpc_args,
                               void* cb_user_data);

  void start();

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


  // which session would this go out?  i.e. can this client_service support multiple sessions?
  void call_remote_rpc() {}

  // how do we find out the list of remote topics? and if we have multiple
  // sessions, then, which session has the topic we want?
  void subscribe_remote_topic() {}

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
  void handle_session_state_change(session_handle, bool is_open);

  void register_procedures();

  void new_client(IOHandle *hndl,
                  int  status,
                  tcp_connect_attempt_cb user_cb,
                  void* user_data);

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

  t_client_request_id  m_next_internal_request_id;

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


  std::map<std::pair<std::string,int>, router_session*> m_router_sessions;
  std::mutex m_router_sessions_lock;
};

} // namespace XXX

#endif
