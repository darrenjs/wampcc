#ifndef XXX_DEALER_SERVICE_H
#define XXX_DEALER_SERVICE_H


#include "Callbacks.h"

#include <jalson/jalson.h>

#include <list>
#include <memory>
#include <mutex>

namespace XXX {

  class SessionMan;
  class Session;
  class pubsub_man;
  class rpc_man;
  class Logger;
  struct rpc_details;
  class event;
  class IOLoop;
  class IOHandle;
  class event_loop;
  class ev_inbound_message;

struct dealer_listener
{
  virtual void rpc_registered(std::string uri) = 0;
};

class dealer_service
{
public:

  dealer_service(Logger*, dealer_listener*, IOLoop* io, event_loop* ev /*, internal_invoke_cb internal_rpc_cb */);
  ~dealer_service();

  void start();

  void listen(int port);

  // int register_internal_procedure(std::string procedure,
  //                                 const std::string& realm);

  void register_procedure(const std::string& realm,
                          const std::string& uri,
                          const jalson::json_object& options,
                          rpc_cb cb,
                          void * data);


  bool reply(t_invoke_id,
             bool is_error,
             wamp_args& the_args);

  // TODO: have a register proc interface

private:
  dealer_service(const dealer_service&) = delete;
  dealer_service& operator=(const dealer_service&) = delete;

  void rpc_registered_cb(const rpc_details&);
  void handle_YIELD(event* ev);
  void handle_SUBSCRIBE(event* ev);
  void handle_CALL(ev_inbound_message*);

  void invoke_procedure(rpc_details&,
                        ev_inbound_message*);

  // essential components
  Logger *__logptr; /* name chosen for log macros */
  IOLoop*  m_io_loop;
  event_loop* m_evl;
  bool m_own_io;
  bool m_own_ev;

  std::unique_ptr<SessionMan> m_sesman;
  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

//  internal_invoke_cb m_internal_invoke_cb;

  dealer_listener* m_listener;

  // note, this is not to be confused with the request ID which is included with
  // a WAMP message send to a peer
  unsigned int m_next_internal_request_id;

  // TODO: move to impl
  struct pending_request
  {
    call_user_cb cb;
    std::string procedure;
    void* user_cb_data;

    session_handle call_source;
    int call_request_id;
    bool is_external;

    pending_request() : user_cb_data( nullptr ),is_external(false) { }
  };

  std::map<int, pending_request> m_pending_requests;
  std::mutex m_pending_requests_lock;



  struct proc_invoke_context
  {
    session_handle seshandle;
    int requestid;
  };
  size_t m_next_call_id = 1001;
  std::map <size_t, proc_invoke_context>  m_calls;
  std::mutex                              m_calls_lock;

};

} // namespace

#endif
