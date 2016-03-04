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
  class rpc_man;
  class Logger;
  struct rpc_details;
  class event;
  class IOLoop;
  class IOHandle;
  class event_loop;


struct dealer_listener
{
  virtual void rpc_registered(std::string uri) = 0;
};


class dealer_service
{
public:

  dealer_service(Logger*, dealer_listener*);
  ~dealer_service();

  void start();

  // TODO: the whole connector business shoudl be in a separate object
  void connect(const std::string & addr,
               int port,
               tcp_connect_attempt_cb user_cb,
               void* user_data);

  /* Call an RPC registered within the dealer service */
  unsigned int call_rpc(std::string rpc, call_user_cb, rpc_args, void* cb_user_data);

private:
  dealer_service(const dealer_service&) = delete;
  dealer_service& operator=(const dealer_service&) = delete;

  void rpc_registered_cb(const rpc_details*);
  void handle_YIELD(event* ev);


  // essential components
  Logger *__logptr; /* name chosen for log macros */
  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;

  std::unique_ptr<SessionMan> m_sesman;
  std::unique_ptr<rpc_man> m_rpcman;

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

    pending_request() : user_cb_data( nullptr ) { }
  };

  std::map<int, pending_request> m_pending_requests;
  std::mutex m_pending_requests_lock;
};

} // namespace

#endif
