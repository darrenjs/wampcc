#include "rpc_man.h"

#include "event_loop.h"
#include "kernel.h"
#include "Logger.h"
#include "wamp_session.h"

#include <memory>

namespace XXX {



/* Constructor */
rpc_man::rpc_man(kernel& k, rpc_added_cb cb)
  : __logptr(k.get_logger()),
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

  {
    std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
    auto realm_iter = m_realm_to_registry.find( realm );

    // TODO: all this code for inserting a new RPC is dupliacted in another part
    // of this file.
    if (realm_iter == m_realm_to_registry.end())
    {
      // insert realm
      auto p = m_realm_to_registry.insert(std::make_pair(realm, rpc_registry()));
      realm_iter = std::move(p.first);
    }

    auto rpc_iter = realm_iter->second.find(uri);
    if (rpc_iter != realm_iter->second.end())
    {
      // TODO: dont throw here; instead just return to the internal caller, ie
      // we are trying to register an internal RPC here, so throwing an event
      // error is not the right thing to do.
      _WARN_("Ignoring duplicate rpc registration for " << realm << ":" << uri);
      throw event_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    }

    // create registration record

    r.registration_id = m_next_regid++;
    realm_iter->second[ uri ] = std::move(r);
  }

  _INFO_( "Internal  "<< realm << "::'" << uri <<"' registered with id " << r.registration_id );

  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r.registration_id;
}


uint64_t rpc_man::handle_inbound_register(session_handle sh,
                                          std::string realm,
                                          std::string uri)
{
  /* EV thread */

  rpc_details r;
  r.registration_id = 0;
  r.uri = std::move(uri);
  r.session = sh;
  r.type = rpc_details::eRemote;

  {
    std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
    auto realm_iter = m_realm_to_registry.find( realm );

    if (realm_iter == m_realm_to_registry.end())
    {
      // insert realm
      auto p = m_realm_to_registry.insert(std::make_pair(realm, rpc_registry()));
      realm_iter = std::move(p.first);
    }

    auto rpc_iter = realm_iter->second.find(uri);
    if (rpc_iter != realm_iter->second.end())
    {
      _WARN_("Ignore duplicate procedure register for " << realm << ":" << uri);
      throw event_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    }

    // create registration record

    r.registration_id = m_next_regid++;
    realm_iter->second[ uri ] = r;

  }

  _INFO_( "Procedure "<< realm << "::'" << uri <<"' registered with id " << r.registration_id );

  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r.registration_id;
}



} // namespace XXX
