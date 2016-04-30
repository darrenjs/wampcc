#include "rpc_man.h"

#include "event_loop.h"
#include "SessionMan.h"
#include "Logger.h"

#include <memory>

namespace XXX {



/* Constructor */
rpc_man::rpc_man(Logger * logptr, event_loop&evl, SessionMan* sm, rpc_added_cb cb,
                 internal_invoke_cb internal_rpc_cb)
  : __logptr(logptr),
    m_evl(evl),
    m_sesman(sm),
    m_next_regid(1),
    m_rpc_added_cb( cb ),
    m_internal_invoke_cb( internal_rpc_cb )
{
  m_evl.set_rpc_man( this );
}

/* Destructor */
rpc_man::~rpc_man()
{
  for (auto & item : m_rpc_map2)
  {
    delete item.second;
  }
}


// TODO: instead of int, use a typedef
int rpc_man::register_internal_rpc(const std::string& procedure_uri,
                                   const std::string& realm)
{
  rpc_details* r = new rpc_details();
  r->registration_id = 0;
  r->uri = procedure_uri;
  r->type = rpc_details::eInternal;

  // {
  //   std::lock_guard< std::mutex > guard ( m_rpc_map_lock );

  //   auto & rpcreg = m_realm_to_registry [ realm ];
  //   // TODO: handle duplicates
  //   r->registration_id = m_next_regid++;
  //   rpcreg[ procedure_uri ] = r;
  // }
  // if (m_rpc_added_cb) m_rpc_added_cb( r );
  // return r->registration_id;

  // ---


  {
    std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
    auto realm_iter = m_realm_to_registry.find( realm );

    if (realm_iter == m_realm_to_registry.end())
    {
      // insert realm

    }

    auto rpc_iter = realm_iter->second.find(procedure_uri);
    if (rpc_iter != realm_iter->second.end())
    {
      _WARN_("Ignoring duplicate rpc registration for " << realm << ":" << procedure_uri);
      throw event_error(WAMP_ERROR_PROCEDURE_ALREADY_EXISTS);
    }

    // create registration record

    r->registration_id = m_next_regid++;
    realm_iter->second[ procedure_uri ] = r;

  }

  _INFO_( "Internal  "<< realm << "::'" << procedure_uri <<"' registered with id " << r->registration_id );


  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r->registration_id;
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

  return *rpc_iter->second;
}

// TODO: would be nice if jalson has better checking method, and doesnt throw
bool has_child(jalson::json_array& jv, size_t i, jalson::JSONType t)
{
  return (jv.size()>i && jv[i].type() == t);
}

void rpc_man::handle_invocation(jalson::json_array& /*jv*/)
{
  /* Handle an inbound INVOCATION request

   */
}
void rpc_man::invoke_rpc(jalson::json_array& /*jv*/)
{

  /* TODO: not sure if this code is used.  it does look complete, however i have
           not yet got to stage of handling calls.

           Update 24/01/16 -- have not commented it out; since the final 'cb'
           called failed.  It stopped compiling once I added the client_service
           into the RPC callback signature.

   */

/* [
     0 CALL,
     1 Request|id,
     2 Options|dict,
     3 Procedure|uri,
     4 Arguments|list,
     5 ArgumentsKw|dict
   ]
*/

  // jalson::json_array * arg_list;
  // jalson::json_object* arg_dict;

  // if (!has_child(jv, 1, jalson::eINTEGER))
  //   throw event_error::runtime_fatal( "missing or malformed request ID");

  // if (!has_child(jv, 3, jalson::eSTRING))
  //   throw event_error(WAMP_ERROR_INVALID_URI);

  // // TODO: need a check-optional here

  // uint64_t requestid  = jv[1].as_uint();
  // const std::string& procedure_uri = jv[3].as_string();

  // if (jv.size()>4 && jv[4].type() == jalson::eARRAY)
  //   arg_list = &  jv[4].as_array();

  // if  (jv.size()>5 && jv[5].type() == jalson::eOBJECT)
  //   arg_dict = & jv[5].as_object();

  // std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
  // auto it = m_rpc_map.find( procedure_uri );

  // if (it == m_rpc_map.end())
  //   throw event_error(WAMP_URI_NO_SUCH_PROCEDURE,"RPC not found");

  // rpc_cb& cb = it->second.first;
  // cb(requestid, arg_list, arg_dict, it->second.second);
}

int rpc_man::handle_inbound_REGISTER(ev_inbound_message* ev)
{
  //int size = ja.size();
  const std::string& procedure_uri = jalson::get_ref(ev->ja, 3).as_string();

  rpc_details* r = new rpc_details();
  r->registration_id = 0;
  r->uri = procedure_uri;
  r->sesionh = ev->src;
  r->type = rpc_details::eRemote;


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

    r->registration_id = m_next_regid++;
    realm_iter->second[ procedure_uri ] = r;

  }

  _INFO_( "Procedure "<< ev->realm << "::'" << procedure_uri <<"' registered with id " << r->registration_id );


  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r->registration_id;
}

// Start a CALL sequence to an RPC
void rpc_man::call_rpc(std::string rpcname)
{

  _ERROR_("TODO: delete this function");
  // rpc_details r;
  // {
  //   std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
  //   auto it = m_rpc_map2.find( rpcname );
  //   if (it == m_rpc_map2.end())
  //     throw std::runtime_error("dont have that RPC");
  //   r = *(it->second);
  // }

  /*
  HERE: I am trying to figure out have to route a USER request to CALL an RPC into a sequence of calls
        that ends with a message being sent out of the Session socket.  Do I need to go via the event
        loop?  And does INVOKE have a request ID? If so, where is that piece of code that manages
        the request/response correspondence.  And how does the result can invoked on the USER CALLBACK?
  */

  // Build the INVOKE request. TODO: should I call the session man directly
  // here? Or, do it via the event thread?  Not sure.  Note that there will be
  // two CALL sequences; one when it is coming direct from the User, and the
  // other when it comes from a client_service that is connected to a dealer.

  /*
                  dealer_server
    USER -->       call_rpc     --->   m_rpcman   --> SessionMan
                      + SID                              +Session

   */


}

// void rpc_man::handle_inbound_CALL(ev_inbound_message* ev)
// {
//   // TODO: improve json parsing
//   std::string uri = ev->ja[3].as_string();

//   /* lookup the RPC */

//   // TODO: use direct lookup here, instead of that call to public function, wheich can then be deprecated
//   rpc_details rpc = this->get_rpc_details(uri, ev->realm);

//   if (rpc.registration_id)
//   {
//     if (rpc.type == rpc_details::eInternal)
//     {
//       _INFO_("TODO: have an internal rpc to handle " << uri);

//       //  m_internal_rpc_invocation(src, registrationid, args, reqid);
//       if (m_internal_invoke_cb)
//       {
//         t_request_id reqid = ev->ja[1].as_int();
//         wamp_args my_wamp_args;

//         if ( ev->ja.size() > 4 ) my_wamp_args.args_list = ev->ja[ 4 ].as_array();
//         m_internal_invoke_cb( ev->src,
//                               reqid,
//                               rpc.registration_id,
//                               my_wamp_args);
//       }
//     }
//     else
//     {
//       // TODO:need to create INVPOKE?
//       _INFO_("TODO: have an outbound rpc to handle " << uri);

//       build_message_cb_v2 msg_builder2 = [&](int request_id)
//         {
//           jalson::json_array msg;
//           msg.push_back( INVOCATION );
//           msg.push_back( request_id );
//           msg.push_back( rpc.registration_id );
//           msg.push_back( jalson::json_object() );
//           msg.push_back( jalson::json_array() );
//           msg.push_back( jalson::json_object() );

//           return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
//                                                                     nullptr );
//         };

//       m_sesman->send_request( rpc.sesionh, INVOCATION, ev->internal_req_id, msg_builder2);
//     }
//   }
//   else
//   {
//     _WARN_("Failed to find RPC for CALL request: " << uri);
//      // TODO : test this path; should reulst in a ERROR going back to the
//      // client process, and that it can successfully handle it.
//     throw event_error(WAMP_ERROR_URI_NO_SUCH_PROCEDURE);
//   }

// }

} // namespace XXX
