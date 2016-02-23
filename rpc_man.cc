#include "rpc_man.h"

#include "event_loop.h"
#include "Logger.h"

#include <memory>

namespace XXX {



/* Constructor */
rpc_man::rpc_man(Logger * logptr, event_loop&evl, rpc_added_cb cb)
  : __logptr(logptr),
    m_evl(evl),
    m_next_regid(1),
    m_rpc_added_cb( cb )
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


void rpc_man::register_internal_rpc(const std::string& rpc_uri)
{
  std::lock_guard< std::mutex > guard ( m_rpc_map_lock );

  // TODO: handle duplicates
  rpc_details* myrpc = new rpc_details();
  myrpc->type = rpc_details::eInternal;
  m_rpc_map2[ rpc_uri ] = myrpc;

}


rpc_details rpc_man::get_rpc_details( std::string rpcname )
{
  std::lock_guard< std::mutex > guard ( m_rpc_map_lock );

  // std::cout << "RPCs: ";
  // for (auto i : m_rpc_map2)
  // {
  //   std::cout << i.second->rpc_name << " ";
  // }
  // std::cout << "\n";

  auto it = m_rpc_map2.find( rpcname );
  if (it != m_rpc_map2.end())
  {
    return *(it->second);
  }
  else
    return rpc_details();
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

int rpc_man::handle_register_event(SID src,
                                   jalson::json_array& ja)
{
  //int size = ja.size();
  const std::string& procedure_uri = ja[3].as_string();

  rpc_details* r = new rpc_details();
  r->registration_id = 0;
  r->uri = procedure_uri;
  r->sid = src;

  {
    r->registration_id = m_next_regid++;
    std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
    m_rpc_map2[ procedure_uri ] = r;
  }

  _INFO_( "RPC '" << procedure_uri <<"' registered with id " << r->registration_id );

  if (m_rpc_added_cb) m_rpc_added_cb( r );
  return r->registration_id;

}

// Start a CALL sequence to an RPC
void rpc_man::call_rpc(std::string rpcname)
{
  rpc_details r;
  {
    std::lock_guard< std::mutex > guard ( m_rpc_map_lock );
    auto it = m_rpc_map2.find( rpcname );
    if (it == m_rpc_map2.end())
      throw std::runtime_error("dont have that RPC");
    r = *(it->second);
  }

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

} // namespace XXX
