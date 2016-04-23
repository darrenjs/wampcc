#ifndef XXX_RPC_MAN_H
#define XXX_RPC_MAN_H

#include "WampTypes.h"
#include "Callbacks.h"

#include <jalson/jalson.h>


#include <functional>
#include <map>
#include <string>
#include <mutex>
#include <memory>

namespace XXX {

class event_loop;
class client_service;
class Logger;
class ev_inbound_message;


struct rpc_details
{
  enum
  {
    eInternal,
    eRemote
  } type;

  int         registration_id; // 0 implies invalid
  std::string uri;
  SID sid;
  session_handle sesionh;
  rpc_details() : registration_id( 0 ) {}
};

typedef std::function< void(const rpc_details*) > rpc_added_cb;

class rpc_man
{
public:
  rpc_man(Logger *, event_loop&, rpc_added_cb, internal_invoke_cb);
  ~rpc_man();

  // handle an inbound CALL event
  void handle_inbound_CALL(ev_inbound_message*);

  // return the registion id
  int  handle_register_event(session_handle& sh,
                             jalson::json_array&);

  // TODO: what is this for?
  void invoke_rpc(jalson::json_array& jv);
  // TODO: what is this for?
  void handle_invocation(jalson::json_array& jv);

  // Register and RPC that is handled by the internal session
  int register_internal_rpc(const std::string& rpc_uri,
                            const std::string& realm);

  // Start a CALL sequence to an RPC
  void call_rpc(std::string rpcname);

  rpc_details get_rpc_details( const std::string& rpcname,
                               const std::string& realm);

private:
  rpc_man(const rpc_man&); // no copy
  rpc_man& operator=(const rpc_man&); // no assignment

  Logger *__logptr; /* name chosen for log macros */
  event_loop& m_evl;

  typedef  std::map< std::string, rpc_details* > rpc_registry;
  typedef  std::map< std::string, rpc_registry > realm_to_rpc_registry;

  std::mutex       m_rpc_map_lock;
  realm_to_rpc_registry m_realm_to_registry;
  std::map< std::string, rpc_details* > m_rpc_map2;
  int m_next_regid;
  rpc_added_cb     m_rpc_added_cb;
  internal_invoke_cb m_internal_invoke_cb;
};

} // namespace XXX

#endif
