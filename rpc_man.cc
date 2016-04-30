#include "rpc_man.h"

#include "event_loop.h"
#include "Logger.h"

#include <memory>

namespace XXX {



/* Constructor */
rpc_man::rpc_man(Logger * logptr, event_loop&evl, rpc_added_cb cb)
  : __logptr(logptr),
    m_rpc_added_cb(cb),
    m_next_regid(1)
{
  evl.set_rpc_man( this );
}


// TODO: instead of int, use a typedef
int rpc_man::register_internal_rpc(const std::string& procedure_uri,
                                   const std::string& realm)
{
  rpc_details r;
  r.registration_id = 0;
  r.uri = procedure_uri;
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

    auto rpc_iter = realm_iter->second.find(procedure_uri);
    if (rpc_iter != realm_iter->second.end())
    {
      _WARN_("Ignoring duplicate rpc registration for " << realm << ":" << procedure_uri);
      throw event_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    }

    // create registration record

    r.registration_id = m_next_regid++;
    realm_iter->second[ procedure_uri ] = std::move(r);

  }

  _INFO_( "Internal  "<< realm << "::'" << procedure_uri <<"' registered with id " << r.registration_id );


  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r.registration_id;
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


int rpc_man::handle_inbound_REGISTER(ev_inbound_message* ev)
{
  //int size = ja.size();
  const std::string& procedure_uri = jalson::get_ref(ev->ja, 3).as_string();

  rpc_details r;
  r.registration_id = 0;
  r.uri = procedure_uri;
  r.sesionh = ev->src;
  r.type = rpc_details::eRemote;


  {
    std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
    auto realm_iter = m_realm_to_registry.find( ev->realm );

    if (realm_iter == m_realm_to_registry.end())
    {
      // insert realm
      auto p = m_realm_to_registry.insert(std::make_pair(ev->realm, rpc_registry()));
      realm_iter = std::move(p.first);
    }

    auto rpc_iter = realm_iter->second.find(procedure_uri);
    if (rpc_iter != realm_iter->second.end())
    {
      _WARN_("Ignore duplicate procedure register for " << ev->realm << ":" << procedure_uri);
      throw event_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    }

    // create registration record

    r.registration_id = m_next_regid++;
    realm_iter->second[ procedure_uri ] = r;

  }

  _INFO_( "Procedure "<< ev->realm << "::'" << procedure_uri <<"' registered with id " << r.registration_id );


  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r.registration_id;
}


} // namespace XXX
