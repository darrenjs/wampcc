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
  rpc_cb user_cb; // applies only for eInternal
  void*  user_data; // applies only for eInternal
  rpc_details() : registration_id( 0 ) {}
};

typedef std::function< void(const rpc_details&) > rpc_added_cb;

class rpc_man
{
public:
  rpc_man(Logger *, rpc_added_cb);

  // return the registion id
  int handle_inbound_REGISTER(ev_inbound_message*);

  // Register and RPC that is handled by the internal session
  int register_internal_rpc_2(const std::string& realm,
                              const std::string& uri,
                              const jalson::json_object& options,
                              rpc_cb cb,
                              void * data);



  rpc_details get_rpc_details( const std::string& rpcname,
                               const std::string& realm);

private:
  rpc_man(const rpc_man&); // no copy
  rpc_man& operator=(const rpc_man&); // no assignment

  Logger *__logptr; /* name chosen for log macros */
  rpc_added_cb m_rpc_added_cb;

  typedef  std::map< std::string, rpc_details >  rpc_registry;
  typedef  std::map< std::string, rpc_registry > realm_to_rpc_registry;

  std::mutex m_rpc_map_lock;
  realm_to_rpc_registry m_realm_to_registry;
  int m_next_regid;


};

} // namespace XXX

#endif
