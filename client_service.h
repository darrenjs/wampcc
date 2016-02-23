#ifndef XXX_CLIENT_SERVICE_H
#define XXX_CLIENT_SERVICE_H

#include "SID.h"
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
  };

  client_service(Logger*, config);
  ~client_service();

  void start();

  /* Register a procedure */
  void add_procedure(const std::string& uri,
                     rpc_cb cb,
                     void * data);

  /* Used by the CALLEE to respond to a procedure call */
  void post_reply(t_sid session,
                  t_request_id request_id,
                  rpc_args& the_args);

  /* Used by the CALLEE to respond to a procedure call */
  void post_error(t_sid session,
                  t_request_id request_id,
                  std::string& error);

  void add_topic()     {}


  // which session would this go out?  i.e. can this client_service support multiple sessions?
  void call_remote_rpc() {}

  // how do we find out the list of remote topics? and if we have multiple
  // sessions, then, which session has the topic we want?
  void subscribe_remote_topic() {}

  void new_client(IOHandle *);

private:
  client_service(const client_service&) = delete;
  client_service& operator=(const client_service&) = delete;

  void handle_REGISTERED(class event*);
  void handle_INVOCATION(class event*);
  void handle_session_state_change(Session*, bool is_open);

  void register_procedures();

  void on_io_timer();
  void on_io_async();

  Logger *__logptr; /* name chosen for log macros */

  config m_config;

  std::map< std::string, std::pair< rpc_cb,void*> > m_procedures;
  std::mutex                                        m_procedures_lock;


  struct RegistrationKey
  {
    SID s;
    int id;
    bool operator<(const RegistrationKey& k) const;
  };
  std::map <RegistrationKey, std::string>           m_registrationid_map;
  std::mutex                                        m_registrationid_map_lock;


  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
  std::unique_ptr<SessionMan> m_sesman;
};

} // namespace XXX

#endif
