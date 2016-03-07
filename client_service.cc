#include "client_service.h"

#include "IOHandle.h"
#include "SessionMan.h"
#include "Session.h"
#include "WampTypes.h"
#include "Logger.h"
#include "utils.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"
#include "Topic.h"
#include "dealer_service.h"

#include <iostream>

#include <unistd.h>
#include <string.h>


namespace XXX {



struct Request_Register_CD_Data : public Request_CB_Data
{
  std::string procedure;
};


bool client_service::RegistrationKey::operator<(const RegistrationKey& rhs) const
{
  return ( (this->s < rhs.s) or ((this->s == rhs.s) and (this->id < rhs.id) ) );
}

//----------------------------------------------------------------------

/* Constructor */
client_service::client_service(Logger * logptr,
                               config config)
  : __logptr( logptr),
    m_config( config ),
    m_io_loop( new IOLoop(logptr) ),
    m_evl( new event_loop(logptr) ),
    m_sesman(new SessionMan(__logptr, *m_evl.get())),
    m_next_client_request_id(100)
{
  _INFO_("client_service::client_service");
  m_evl->set_session_man( m_sesman.get() );

  m_sesman->set_session_event_listener(
    [this](session_handle sh, bool b){this->handle_session_state_change(sh,b);});

  // m_evl.set_handler(CHALLENGE,
  //                   [this](class event* ev){ this->handle_CHALLENGE(ev); } );

  m_evl->set_handler2(REGISTERED,
                      [this](inbound_message_event* ev){ this->handle_REGISTERED(ev); } );

  m_evl->set_handler2(INVOCATION,
                      [this](inbound_message_event* ev){ this->handle_INVOCATION(ev); } );

  m_evl->set_handler2(RESULT,
                      [this](inbound_message_event* ev){ this->handle_RESULT(ev); } );

  m_evl->set_handler2(ERROR,
                      [this](inbound_message_event* ev){ this->handle_ERROR(ev); } );

  m_evl->m_internal_invoke_cb = [this](session_handle& h,
                                       t_request_id req_id,
                                       int reg_id,
                                       rpc_args& args){this->invoke_direct(h, req_id, reg_id, args);};

  m_io_loop->m_new_client_cb = [this](IOHandle* h, int status ,tcp_connect_attempt_cb user_cb, void* user_data ){this->new_client(h, status, user_cb, user_data);};

  if (config.enable_embed_router)
  {
    m_embed_router = new dealer_service(logptr, nullptr, m_io_loop.get(), m_evl.get());
  }
}

//----------------------------------------------------------------------

/* Destructor */
client_service::~client_service()
{
  _INFO_("client_service::~client_service");

  // TODO: dont think this is the best way to shutdown.  Should start by trying
  // to close all the sessions.
  m_io_loop->stop();
  m_evl->stop();

  if (m_embed_router) delete m_embed_router;

  m_evl.reset();
}

void client_service::handle_session_state_change(session_handle sh, bool is_open)
{
  if (is_open == false)
  {
    auto sp = sh.lock();
    if (sp)
    {
      std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
      for (auto it = m_registrationid_map.begin(); it!=m_registrationid_map.end();)
      {
        if (it->first.s == *sp)
        {
          //_INFO_("erasing registion " << *sp);
          m_registrationid_map.erase( it++ );
        }
        else ++it;
      }
    }
    return;
  }

  _INFO_("session is now ready ... registering procedures");

  // TODO: this must come only after we have been authenticated
  // register our procedures
  {
    std::lock_guard< std::mutex > guard ( m_procedures_lock );

    for (auto i : m_procedures)
    {
      const std::string & procedure = i.first;

      build_message_cb_v2 msg_builder2 = [&procedure](int request_id)
        {
          /* WAMP spec.
             [
             INVOCATION,
             Request|id,
             REGISTERED.Registration|id,
             Details|dict
             CALL.Arguments|list,
             CALL.ArgumentsKw|dict
             ]
          */

          jalson::json_array msg;
          msg.push_back( REGISTER );
          msg.push_back( request_id );
          msg.push_back( jalson::json_object() );
          msg.push_back( procedure );

          Request_Register_CD_Data * cb_data = new Request_Register_CD_Data(); // TODO: memleak?
          cb_data->procedure = procedure;

          // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
          return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
                                                                    cb_data );

        };

      // TODO: instead of 0, need to have a valie intenral request id
      m_sesman->send_request(sh, REGISTER, 0, msg_builder2);
    }
  }

  // publish our topics
  {
    std::lock_guard< std::mutex > guard ( m_topics_lock );
    for (auto i : m_topics)
    {
      const std::string & uri = i.first;
      build_message_cb_v2 msg_builder2 = [&uri](int request_id)
        {
          /* WAMP spec.
             [
             PUBLISH,
             Request|id,
             Options|dict,
             Topic|uri,
             Arguments|list,
             ArgumentsKw|dict
             ]
          */

          jalson::json_array msg;
          msg.push_back( PUBLISH );
          msg.push_back( request_id );
          msg.push_back( jalson::json_object() );
          msg.push_back( uri );

          // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
          return std::pair< jalson::json_array, Request_CB_Data*> ( msg, nullptr );

        };

      // TODO: instead of 0, need to have a valie intenral request id
      m_sesman->send_request(sh, PUBLISH, 0, msg_builder2);
    }

  }
}

//----------------------------------------------------------------------

void client_service::new_client(IOHandle *h,
                                int  status,
                                tcp_connect_attempt_cb user_cb,
                                void* user_data)
{
  _INFO_("client_service::new_client");
  /* === Called on IO thread === */

  std::string the_realm="default";
  tcp_connect_event * ev = new tcp_connect_event(user_cb, user_data, status);

  if (h)
  {
    Session* sptr = m_sesman -> create_session(h, false);
    ev->src = sptr->handle();

    // TODO: probably want to move this into the Session
    {
      jalson::json_array msg;
      msg.push_back( HELLO );
      msg.push_back( the_realm );
      jalson::json_object& opt = jalson::append_object( msg );
      opt[ "roles" ] = jalson::json_object();
      opt[ "authid"] = "peter";
      opt[ "authmethods"] = jalson::json_array({"wampcra"});
      sptr->send_msg( msg );
    }
  }

  m_evl->push( ev );
}

//----------------------------------------------------------------------

void client_service::start()
{
  m_io_loop->start(); // returns immediately

  if (m_config.enable_embed_router)
  {
    // TODO: here, I need to register my procedure with the internal router
    std::map< std::string, int > regid;
    {
      std::lock_guard< std::mutex > guard ( m_procedures_lock );
      for (auto i : m_procedures)
      {
        const std::string & uri = i.first;
        int registrationid = m_embed_router->register_procedure(uri);
        regid[ uri ] = registrationid;
      }
    }

    {
      std::unique_lock<std::mutex> guard(m_registrationid_map_lock2);
      for (auto i : regid)
      {
        m_registrationid_map2[ i.second ] = i.first;
      }
    }

    m_embed_router->start();
    m_embed_router->listen(m_config.port);
  }

  // TODO: this is where the client used to listen, so revert/delete
  // if (m_config.port )
  //   m_io_loop->add_server( m_config.port );
}

//----------------------------------------------------------------------

bool client_service::add_procedure(const std::string& uri,
                                   rpc_cb cb,
                                   void * user)
{
  auto mypair = std::make_pair(cb, user);

  std::lock_guard< std::mutex > guard ( m_procedures_lock );
  auto it = m_procedures.find( uri );

  if (it == m_procedures.end())
  {
    m_procedures.insert( std::make_pair(uri, mypair) );
    return true;
  }
  else
    return false;
}

//----------------------------------------------------------------------

void client_service::handle_REGISTERED(inbound_message_event* ev)
{
  Request_Register_CD_Data* cb_data = nullptr;

  if (ev && ev->cb_data)
  {
    cb_data = dynamic_cast<Request_Register_CD_Data*>(ev->cb_data); // DJS, core here
  }

  if (cb_data)
  {
    // TODO: check, what type does WAMP allow here?
    int registration_id = ev->ja[2].as_sint();

    if (auto sp = ev->src.lock())
    {
      RegistrationKey key;
      key.s  = *sp;
      key.id = registration_id;


      // OKAY: when I sent a REGISTER request, I did not store the REQUEST ID
      // anywhere, did I ? So I need to find that request, and store it.  Wheere is
      // the best place to store it?
      {
        std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
        m_registrationid_map[ key ] = cb_data->procedure;
      }
      _INFO_("procedure '" << cb_data->procedure << "' registered with key "
             << key.s << ":" << key.id);
    }
  }
  else
  {
    _ERROR_( "ERROR: failed to process end-point registered message; no cb_data");
  }
}

//----------------------------------------------------------------------

void client_service::handle_INVOCATION(inbound_message_event* ev) // change to lowercase
{
  auto sp = ev->src.lock();
  if (!sp)
  {
    // TODO: add handler for this situation
    return;
  }

  // TODO: need to parse the INVOCATION message here, eg, check it is valid
  RegistrationKey rkey;
  rkey.s  = *sp;
  rkey.id = ev->ja[2].as_sint();

  std::string procname;
  {
    std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
    auto it = m_registrationid_map.find(rkey);

    // for (auto i : m_registrationid_map)
    // {
    //   std::cout << "key " << i.first << "\n";
    // }

    if (it == m_registrationid_map.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       ev->ja[1].as_sint());
    }
    procname = it->second;
  }

  std::pair< rpc_cb,void*> rpc_actual;
  {
    std::unique_lock<std::mutex> guard(m_procedures_lock);
    auto it = m_procedures.find( procname );

    if (it == m_procedures.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       ev->ja[1].as_sint());
    }
    rpc_actual = it->second;
  }

  _INFO_( "invoke lookup success, key " << rkey.s <<":"<<rkey.id  << " -> " << procname );

  rpc_args my_rpc_args;
  if ( ev->ja.size() > 4 ) my_rpc_args.args = ev->ja[ 4 ];

  t_request_id reqid = ev->ja[1].as_sint(); // TODO: make a helper for this, ie, json to t_requetst_id

  if (rpc_actual.first)
  {
    size_t mycallid = 0;
    bool had_exception = true;
    {
      // TODO: need to ensure we cannt take the 0 value, and that our valid is avail
      std::unique_lock<std::mutex> guard(m_calls_lock);
      mycallid = ++m_callid;
//      m_calls[ mycallid ] . s = rkey.s;  --- looks like error?
      m_calls[ mycallid ] . seshandle = ev->src;
      m_calls[ mycallid ] . requestid = reqid;
      m_calls[ mycallid ] . internal = false;
    }
    // TODO: during exception, could log more details.
    try
    {
      rpc_actual.first(mycallid, procname,  my_rpc_args, ev->src, rpc_actual.second);
      had_exception = false;
    }
    catch (const std::exception& e)
    {
      const char* what = e.what();
      _WARN_("exception thrown by procedure '"<< procname << "': " << (what?e.what():""));
    }
    catch (...)
    {
      _WARN_("unknown exception thrown by user procedure '"<<procname << "'");
    }

    if (had_exception)
    {
      std::unique_lock<std::mutex> guard(m_calls_lock);
      m_calls.erase( mycallid );
    }
  }

  return;
}

//----------------------------------------------------------------------

void client_service::post_reply(t_invoke_id callid,
                                rpc_args& the_args)
{
  /* user thread or EV thread */

  _INFO_("post_reply");

  call_context context;
  {
    std::unique_lock<std::mutex> guard(m_calls_lock);
    auto it = m_calls.find( callid );
    if (it != m_calls.end())
    {
      context = it->second;
      m_calls.erase( it );
    }
    else
    {
      _ERROR_("unknown callid");
      return;
    }
  }

  if ( context.internal )
  {
    outbound_response_event* ev = new outbound_response_event();

    ev->destination   = context.seshandle;;
    ev->response_type = RESULT;
    ev->request_type  = CALL;
    ev->reqid         = context.requestid;
    ev->args          = the_args;

    m_evl->push( ev );
  }

}

//----------------------------------------------------------------------

void client_service::post_error(t_invoke_id callid,
                                std::string& error_uri)
{
  /* user thread or EVL thread */

  call_context context;
  {
    std::unique_lock<std::mutex> guard(m_calls_lock);
    auto it = m_calls.find( callid );
    if (it != m_calls.end())
    {
      context = it->second;
      m_calls.erase( it );
    }
    else
    {
      _ERROR_("unknown callid");
      return;
    }
  }

  outbound_response_event* ev = new outbound_response_event();

  ev->destination   = context.seshandle;
  ev->response_type = ERROR;
  ev->request_type  = INVOCATION;
  ev->reqid         = context.requestid;
  ev->error_uri     = error_uri;

  m_evl->push( ev );

}

//----------------------------------------------------------------------

void client_service::add_topic(topic* topic)
{
  _INFO_("adding a topic: " << topic->uri() );
  // TODO: check that it is uniqyue
  std::unique_lock<std::mutex> guard(m_topics_lock);
  m_topics[ topic->uri() ] = topic;

}

//----------------------------------------------------------------------

// TODO: the whole connector business should be in a separate object
void client_service::connect(const std::string & addr,
                             int port,
                             tcp_connect_attempt_cb user_cb,
                             void* user_data)
{
  _INFO_("doing connect");
  m_io_loop->add_connection(addr,
                           port,
                           user_cb,
                           user_data);
}

//----------------------------------------------------------------------

/* This was the special interface on the dealer_service API which allows CALL
 * sequences to be triggered by the API client, rather than a traditiona WAMP
 * client (ie, TCP based).  The callback is the entry point into the user code
 * when a YIELD or ERROR is received.
 */
t_client_request_id client_service::call_rpc(session_handle& sh,
                                             std::string proc_uri,
                                             call_user_cb cb,
                                             rpc_args args,
                                             void* cb_user_data)
{
  /* USER thread */

  // TODO: this ID needs to be atomic, because there could be multiple USER threads coming in here.
  t_client_request_id int_req_id = m_next_client_request_id++;

  {
    std::lock_guard<std::mutex> guard( m_pending_requests_lock );
    auto & pending = m_pending_requests[int_req_id];
    pending.cb = cb;
    pending.user_cb_data = cb_user_data;
    pending.rpc= proc_uri;
  }

  internal_outbound_call_event * ev = new internal_outbound_call_event();

  ev->mode = event::eOutbound;
  ev->dest = sh;
  ev->msg_type = CALL;
  ev->rpc_name= proc_uri;
  ev->cb = cb;  // memleak?
  ev->args = args; // memleak?
  ev->cb_user_data = cb_user_data;
  ev->internal_req_id=int_req_id;

  m_evl->push( ev );


  return int_req_id;
}


router_session::router_session(const std::string & __addr,
                               int __port,
                               void* __user_data)
 : addr(__addr),
   port(__port),
   user(__user_data)
{
}

//----------------------------------------------------------------------

// TODO: the whole connector business should be in a separate object
router_session* client_service::connect_to_router(const std::string & addr,
                                                  int port,
                                                  tcp_connect_attempt_cb user_cb,
                                                  void* user_data)
{
  router_session * rs = new router_session(addr,
                                           port,
                                           user_data);
  {
    std::unique_lock<std::mutex> guard(m_router_sessions_lock);
    m_router_sessions[ std::make_pair(addr,port) ] = rs;
  }

  // create the router_session

  // start the connect

  //
  _INFO_("doing connect");
  m_io_loop->add_connection(addr,
                           port,
                           user_cb,
                           user_data);

  return rs;
}


void client_service::invoke_direct(session_handle& sh,
                                   t_request_id req_id,
                                   int reg_id,
                                   rpc_args& args)


{
  _INFO_("direct invoke");
  auto sp = sh.lock();
  if (!sp)
  {
    // TODO: add handler for this situation
    return;
  }

  std::string procname;
  {
    std::unique_lock<std::mutex> guard(m_registrationid_map_lock2);
    auto it = m_registrationid_map2.find(reg_id);

    if (it == m_registrationid_map2.end())
    {
      // TODO: test this, ie, failure during direct CALL
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION, // or CALL?
                                       req_id);
    }
    procname = it->second;
  }
  std::pair< rpc_cb,void*> rpc_actual;
  {
    std::unique_lock<std::mutex> guard(m_procedures_lock);
    auto it = m_procedures.find( procname );

    if (it == m_procedures.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       req_id);
    }
    rpc_actual = it->second;
  }

if (rpc_actual.first)
  {
    size_t mycallid = 0;
    bool had_exception = true;
    {
      // TODO: need to ensure we cannt take the 0 value, and that our valid is avail
      std::unique_lock<std::mutex> guard(m_calls_lock);
      mycallid = ++m_callid;
//      m_calls[ mycallid ] . s = rkey.s;  --- looks like error?
      m_calls[ mycallid ] . seshandle = sh;
      m_calls[ mycallid ] . requestid = req_id;
      m_calls[ mycallid ] . internal  = true;
    }
    // TODO: during exception, could log more details.
    try
    {
      rpc_actual.first(mycallid, procname, args, sh, rpc_actual.second);
      had_exception = false;
    }
    catch (const std::exception& e)
    {
      const char* what = e.what();
      _WARN_("exception thrown by procedure '"<< procname << "': " << (what?e.what():""));
    }
    catch (...)
    {
      _WARN_("unknown exception thrown by user procedure '"<<procname << "'");
    }

    if (had_exception)
    {
      std::unique_lock<std::mutex> guard(m_calls_lock);
      m_calls.erase( mycallid );
    }
  }

}



void client_service::handle_RESULT(inbound_message_event* ev) // change to lowercase
{
  int reqid=ev->ja[1].as_sint();
  _INFO_("Got RESULT for reqid " << reqid << "," << ev->internal_req_id);

  pending_request pendingreq;
  {
    std::lock_guard<std::mutex> guard( m_pending_requests_lock );
    pendingreq = m_pending_requests[ev->internal_req_id]; // TODO: need to erase after this
  }

  if ( pendingreq.cb )
  {
    call_info ci;
    ci.reqid = ev->internal_req_id;
    ci.procedure = pendingreq.rpc;
    rpc_args args;

    // TODO: need parse error checking here
    args.args    = ev->ja[3];
    args.options = ev->ja[2].as_object();

    pendingreq.cb(ci, args, pendingreq.user_cb_data);
  }
  else
  {
    // TODO:  improve this error
    _ERROR_("cannot find pending request, ");
  }
}

void client_service::handle_ERROR(inbound_message_event* ev) // change to lowercase
{
  auto sp = ev->src.lock();
  if (!sp)
  {
    // TODO: add handler for this situation
    return;
  }

  // TODO: need to parse the INVOCATION message here, eg, check it is valid
  RegistrationKey rkey;
  rkey.s  = *sp;
  rkey.id = ev->ja[2].as_sint();

  std::string procname;
  {
    std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
    auto it = m_registrationid_map.find(rkey);

    // for (auto i : m_registrationid_map)
    // {
    //   std::cout << "key " << i.first << "\n";
    // }

    if (it == m_registrationid_map.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       ev->ja[1].as_sint());
    }
    procname = it->second;
  }

  std::pair< rpc_cb,void*> rpc_actual;
  {
    std::unique_lock<std::mutex> guard(m_procedures_lock);
    auto it = m_procedures.find( procname );

    if (it == m_procedures.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       ev->ja[1].as_sint());
    }
    rpc_actual = it->second;
  }

  _INFO_( "invoke lookup success, key " << rkey.s <<":"<<rkey.id  << " -> " << procname );

  rpc_args my_rpc_args;
  if ( ev->ja.size() > 4 ) my_rpc_args.args = ev->ja[ 4 ];

  t_request_id reqid = ev->ja[1].as_sint(); // TODO: make a helper for this, ie, json to t_requetst_id

  if (rpc_actual.first)
  {
    size_t mycallid = 0;
    bool had_exception = true;
    {
      // TODO: need to ensure we cannt take the 0 value, and that our valid is avail
      std::unique_lock<std::mutex> guard(m_calls_lock);
      mycallid = ++m_callid;
//      m_calls[ mycallid ] . s = rkey.s;  --- looks like error?
      m_calls[ mycallid ] . seshandle = ev->src;
      m_calls[ mycallid ] . requestid = reqid;
      m_calls[ mycallid ] . internal = false;
    }
    // TODO: during exception, could log more details.
    try
    {
      rpc_actual.first(mycallid, procname, my_rpc_args, ev->src, rpc_actual.second);
      had_exception = false;
    }
    catch (const std::exception& e)
    {
      const char* what = e.what();
      _WARN_("exception thrown by procedure '"<< procname << "': " << (what?e.what():""));
    }
    catch (...)
    {
      _WARN_("unknown exception thrown by user procedure '"<<procname << "'");
    }

    if (had_exception)
    {
      std::unique_lock<std::mutex> guard(m_calls_lock);
      m_calls.erase( mycallid );
    }
  }

  return;
}

} // namespace XXX
