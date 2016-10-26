#ifndef XXX_RPC_MAN_H
#define XXX_RPC_MAN_H

#include "XXX/types.h"
#include "XXX/wamp_session.h"

#include <jalson/jalson.h>


#include <functional>
#include <map>
#include <string>
#include <mutex>
#include <memory>
#include <list>

namespace XXX {

class event_loop;
struct logger;
class kernel;


struct rpc_details
{
  enum
  {
    eInternal,
    eRemote
  } type;

  int         registration_id; // 0 implies invalid
  std::string uri;
  session_handle session;
  rpc_cb user_cb; // applies only for eInternal
  void*  user_data; // applies only for eInternal
  rpc_details() : registration_id( 0 ) {}
};

typedef std::function< void(const rpc_details&) > rpc_added_cb;

class rpc_man
{
public:
  rpc_man(kernel*, rpc_added_cb);

  // return the registion id
  uint64_t handle_inbound_register(session_handle sh,
                                   std::string realm,
                                   std::string uri);

  // Register and RPC that is handled by the internal session
  int register_internal_rpc_2(const std::string& realm,
                              const std::string& uri,
                              const jalson::json_object& options,
                              rpc_cb cb,
                              void * data);



  rpc_details get_rpc_details( const std::string& rpcname,
                               const std::string& realm);

  void session_closed(std::shared_ptr<wamp_session>&);

private:
  rpc_man(const rpc_man&); // no copy
  rpc_man& operator=(const rpc_man&); // no assignment

  void register_rpc(session_handle, std::string realm, rpc_details& r);

  logger & __logger; /* name chosen for log macros */
  rpc_added_cb m_rpc_added_cb;

  typedef  std::map< std::string, rpc_details >  rpc_registry;
  typedef  std::map< std::string, rpc_registry > realm_to_rpc_registry;

  std::mutex m_rpc_map_lock;
  realm_to_rpc_registry m_realm_to_registry;
  uint64_t m_next_regid;

  std::map<session_handle, std::list<rpc_registry::iterator>,
           std::owner_less<session_handle> > m_rpcs_for_session;

};

} // namespace XXX

#endif
