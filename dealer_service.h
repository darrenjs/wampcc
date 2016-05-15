#ifndef XXX_DEALER_SERVICE_H
#define XXX_DEALER_SERVICE_H


#include "Callbacks.h"
#include "Session.h"

#include <jalson/jalson.h>

#include <list>
#include <memory>
#include <mutex>

namespace XXX {

  class SessionMan;
  class pubsub_man;
  class rpc_man;
  class Logger;
  struct rpc_details;
  class event;
  class IOLoop;
  class IOHandle;
  class event_loop;
  class client_service;

struct dealer_listener
{
  virtual void rpc_registered(std::string uri) = 0;
};

class dealer_service
{
public:
  dealer_service(client_service * __svc, dealer_listener*);
  ~dealer_service();

  // publish to an internal topic
  t_request_id publish(const std::string& topic,
                       const std::string& realm,
                       const jalson::json_object& options,
                       wamp_args);

  void listen(int port);

  void register_procedure(const std::string& realm,
                          const std::string& uri,
                          const jalson::json_object& options,
                          rpc_cb cb,
                          void * data);

private:
  dealer_service(const dealer_service&) = delete;
  dealer_service& operator=(const dealer_service&) = delete;

  void rpc_registered_cb(const rpc_details&);

  t_request_id handle_call(Session*, const std::string&, jalson::json_array & msg, wamp_invocation_reply_fn);

  bool reply(t_invoke_id,
             wamp_args& the_args,
             bool is_error,
             std::string error_uri);

  // essential components
  Logger *__logptr; /* name chosen for log macros */
  IOLoop*  m_io_loop;
  event_loop* m_evl;
  bool m_own_io;
  bool m_own_ev;

  std::unique_ptr<SessionMan> m_sesman;
  std::unique_ptr<rpc_man> m_rpcman;
  std::unique_ptr<pubsub_man> m_pubsub;

  dealer_listener* m_listener;

  // note, this is not to be confused with the request ID which is included with
  // a WAMP message send to a peer
  unsigned int m_next_internal_request_id;

  // TODO: move to impl
  struct pending_request
  {
    wamp_call_result_cb cb;
    std::string procedure;
    void* user_cb_data;

    session_handle call_source;
    t_request_id call_request_id;
    bool is_external;

    pending_request() : user_cb_data( nullptr ),is_external(false) { }
  };

  std::map<int, pending_request> m_pending_requests;
  std::mutex m_pending_requests_lock;



  struct proc_invoke_context
  {
    session_handle seshandle;
    t_request_id requestid;
  };
  size_t m_next_call_id = 1001;
  std::map <size_t, proc_invoke_context>  m_calls;
  std::mutex                              m_calls_lock;

};

} // namespace

#endif
