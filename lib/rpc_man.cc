#include "XXX/rpc_man.h"

#include "XXX/event_loop.h"
#include "XXX/kernel.h"
#include "XXX/log_macros.h"
#include "XXX/wamp_session.h"

#include <memory>

namespace XXX {



/* Constructor */
rpc_man::rpc_man(kernel& k, rpc_added_cb cb)
  : __logger(k.get_logger()),
    m_rpc_added_cb(cb),
    m_next_regid(1)
{
}




rpc_details rpc_man::get_rpc_details( const std::string& rpcname,
                                      const std::string& realm )
{
  std::lock_guard< std::mutex > guard ( m_rpc_map_lock );

  auto realm_iter = m_realm_to_registry.find( realm );

  if (realm_iter == m_realm_to_registry.end())
    return rpc_details(); // realm not found

  auto rpc_iter = realm_iter->second.find(rpcname);
  if (rpc_iter == realm_iter->second.end())
    return rpc_details(); // procedure not found

  return rpc_iter->second;
}


int rpc_man::register_internal_rpc_2(const std::string& realm,
                                     const std::string& uri,
                                     const jalson::json_object& /*options*/,
                                     rpc_cb user_cb,
                                     void * user_data)
{
  rpc_details r;
  r.uri = uri;
  r.user_cb = user_cb;
  r.user_data = user_data;
  r.type = rpc_details::eInternal;

  register_rpc(realm, r);

  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r.registration_id;
}


uint64_t rpc_man::handle_inbound_register(session_handle sh,
                                          std::string realm,
                                          std::string ___uri)
{
  /* EV thread */

  rpc_details r;
  r.registration_id = 0;
  r.uri = std::move(___uri);
  r.session = sh;
  r.type = rpc_details::eRemote;

  register_rpc(realm, r);

  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r.registration_id;
}


void rpc_man::register_rpc(std::string realm, rpc_details& r)
{
  std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
  auto realm_iter = m_realm_to_registry.find( realm );

  // add realm if not already present
  if (realm_iter == m_realm_to_registry.end())
  {
    auto p = m_realm_to_registry.insert(std::make_pair(realm, rpc_registry()));
    realm_iter = std::move(p.first);
  }

  auto rpc_iter = realm_iter->second.find(r.uri);
  if (rpc_iter != realm_iter->second.end())
  {
    LOG_WARN("Ignore duplicate procedure register for " << realm << ":" << r.uri);
    throw wamp_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
  }

  r.registration_id = m_next_regid++;
  realm_iter->second[ r.uri ] = r;

  LOG_INFO( "Procedure "<< realm << "::'" << r.uri <<"' registered with id " << r.registration_id );
}

} // namespace XXX
