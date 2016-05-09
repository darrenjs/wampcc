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
// #include "dealer_service.h"

#include <iostream>

#include <unistd.h>
#include <string.h>


namespace XXX {



struct Request_Register_CD_Data : public Request_CB_Data
{
  std::string procedure;
};



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

  if (m_config.realm.empty()) throw std::runtime_error("config.realm cannot be empty");

  // TODO: make this a member
  client_event_handler local_handler;

  // local_handler.handle_inbound_SUBSCRIBED=
  //   [this](ev_inbound_subscribed* ev) { handle_SUBSCRIBED(ev); };

  // local_handler.handle_inbound_event=
  //   [this](ev_inbound_message* ev) { handle_EVENT(ev); };

  local_handler.handle_router_session_connect_fail=
    [this](ev_router_session_connect_fail* ev) { handle_event(ev); };


  m_evl->set_handler( local_handler );
  m_evl->set_session_man( m_sesman.get() );

  // TODO: remove this, and instead all the client_service directly from the event_loop
  m_sesman->set_session_event_listener(
    [this](ev_session_state_event* ev){this->handle_session_state_change(ev);});

  // m_evl.set_handler(CHALLENGE,
  //                   [this](class event* ev){ this->handle_CHALLENGE(ev); } );

  // m_evl->set_handler2(REGISTERED,
  //                     [this](ev_inbound_message* ev){ this->handle_REGISTERED(ev); } );

  // m_evl->set_handler2(INVOCATION,
  //                     [this](ev_inbound_message* ev){ this->handle_INVOCATION(ev); } );

  // m_evl->set_handler2(RESULT,
  //                     [this](ev_inbound_message* ev){ this->handle_RESULT(ev); } );

  // m_evl->set_handler2(ERROR,
  //                     [this](ev_inbound_message* ev){ this->handle_ERROR(ev); } );


  /* TODO: remove legacy interaction between IO thread and user space */
  m_io_loop->m_new_client_cb = [this](IOHandle* h, int status, int rid ){this->new_client(h, status, rid);};

  // auto fun = [this](session_handle& h ,
  //                   t_request_id  req_id ,
  //                   int reg_id ,
  //                   wamp_args& args ){ this->invoke_direct(h, req_id, reg_id, args); };

  // if (config.enable_embed_router)
  // {
  //   m_embed_router = new dealer_service(logptr, nullptr, m_io_loop.get(), m_evl.get() /*, fun */);
  // }
}

//----------------------------------------------------------------------

/* Destructor */
client_service::~client_service()
{
  // TODO: dont think this is the best way to shutdown.  Should start by trying
  // to close all the sessions.
  m_io_loop->stop();
  m_evl->stop();

  // if (m_embed_router) delete m_embed_router;

  m_evl.reset();
}

//----------------------------------------------------------------------

void client_service::handle_session_state_change(ev_session_state_event* ev)
{
  /* EV thread */

  session_handle sh = ev->src;

  if (! ev->is_open)
  {
    // // remove the RPC registrations that are associated with the connection
    // std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
    // for (auto it = m_registrationid_map.begin(); it!=m_registrationid_map.end();)
    // {
    //   if (it->first.router_session_id == ev->user_conn_id)
    //   {
    //     m_registrationid_map.erase( it++ );
    //   }
    //   else ++it;
    // }

    // raise user callback to indicate session termination
    {
      std::unique_lock< std::mutex > guard(m_router_sessions_lock);
      auto iter = m_router_sessions.find( ev->user_conn_id );
      if (iter != m_router_sessions.end())
      {
        router_conn* rs = iter->second;
        if (rs->m_connection_cb)
          try {
            rs->m_connection_cb(rs, -ev->err, false); // TODO: core dump seen here
          } catch(...){}
      }
    }
    return;
  }

  _INFO_("session is now ready #" << ev->user_conn_id << " ... registering procedures");

  // register our procedures
  // {
  //   std::lock_guard< std::mutex > guard ( m_procedures_lock );

  //   for (auto i : m_procedures)
  //   {
  //     const std::string & procedure = i.first;

  //     build_message_cb_v2 msg_builder2 = [&procedure](int request_id)
  //       {
  //         /* WAMP spec.
  //            [
  //            INVOCATION,
  //            Request|id,
  //            REGISTERED.Registration|id,
  //            Details|dict
  //            CALL.Arguments|list,
  //            CALL.ArgumentsKw|dict
  //            ]
  //         */

  //         jalson::json_array msg;
  //         msg.push_back( REGISTER );
  //         msg.push_back( request_id );
  //         msg.push_back( jalson::json_object() );
  //         msg.push_back( procedure );

  //         Request_Register_CD_Data * cb_data = new Request_Register_CD_Data(); // TODO: memleak?
  //         cb_data->procedure = procedure;

  //         // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
  //         return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
  //                                                                   cb_data );

  //       };

  //     // TODO: instead of 0, need to have a valie intenral request id
  //     m_sesman->send_request(sh, REGISTER, 0, msg_builder2);
  //   }
  // }

  // publish our topics
  {
    std::lock_guard< std::mutex > guard ( m_topics_lock );
    for (auto & i : m_topics)
    {
      const std::string & uri = i.first;
//      topic* topic = i.second;

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
          msg.push_back( jalson::json_array() );

          // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
          return std::pair< jalson::json_array, Request_CB_Data*> ( msg, nullptr );

        };

      // TODO: instead of 0, need to have a valie intenral request id
      m_sesman->send_request(sh, PUBLISH, 0, msg_builder2);
    }

  }

  // raise user callback to indicate session connection
  {
    std::unique_lock< std::mutex > guard(m_router_sessions_lock);
    auto iter = m_router_sessions.find( ev->user_conn_id );
    if (iter != m_router_sessions.end())
    {
      router_conn*  rs = iter->second;
      rs->m_internal_session_handle = sh;
      rs->m_session = m_sesman->get_session(sh);
      if (rs->m_connection_cb)
        try {
          rs->m_connection_cb(rs, 0, true);
        } catch(...){}
    }
  }


}

//----------------------------------------------------------------------

void client_service::new_client(IOHandle *h,
                                int  status,
                                t_connection_id user_conn_id)
{
  /* IO */

  // TODO: bad design here.  IO event should not come to here, and then into the session manager.
  if (h)
  {
    m_sesman -> create_session(h, false, user_conn_id, m_config.realm);
  }
  else
  {
    ev_router_session_connect_fail * ev = new ev_router_session_connect_fail(
      user_conn_id , status);
    m_evl->push( ev );
  }
}

//----------------------------------------------------------------------

void client_service::start()
{
  /* USER thread */

  m_io_loop->start(); // returns immediately

  // if (m_config.enable_embed_router)
  // {
    // // TODO: here, I need to register my procedure with the internal router
    // std::map< std::string, int > regid;
    // {
    //   std::lock_guard< std::mutex > guard ( m_procedures_lock );
    //   for (auto i : m_procedures)
    //   {
    //     const std::string & uri = i.first;
    //     int registrationid = m_embed_router->register_internal_procedure(uri,
    //                                                                      m_config.realm);
    //     regid[ uri ] = registrationid;
    //   }
    // }

    // {
    //   std::unique_lock<std::mutex> guard(m_registrationid_map_lock2);
    //   for (auto i : regid)
    //   {
    //     m_registrationid_map2[ i.second ] = i.first;
    //   }
    // }

    // m_embed_router->start();
    // m_embed_router->listen(m_config.server_port);
  // }

}

//----------------------------------------------------------------------

// bool client_service::add_procedure(const std::string& uri,
//                                    const jalson::json_object& /* options */,
//                                    rpc_cb cb,
//                                    void * user)
// {
//   auto mypair = std::make_pair(cb, user);

//   std::lock_guard< std::mutex > guard ( m_procedures_lock );
//   auto it = m_procedures.find( uri );

//   if (it == m_procedures.end())
//   {
//     m_procedures.insert( std::make_pair(uri, mypair) );
//     return true;
//   }
//   else
//     return false;
// }

//----------------------------------------------------------------------

// void client_service::handle_REGISTERED(ev_inbound_message* ev)
// {
//   Request_Register_CD_Data* cb_data = nullptr;

//   if (ev && ev->cb_data)
//   {
//     cb_data = dynamic_cast<Request_Register_CD_Data*>(ev->cb_data); // DJS, core here
//   }

//   if (cb_data)
//   {
//     // TODO: check, what type does WAMP allow here?
//     int registration_id = ev->ja[2].as_int();

//     {
//       std::unique_lock<std::mutex> guard(m_procedures_lock);
//       procedure_map& pmap = m_procedures[ ev->user_conn_id ];

//       auto iter = pmap.by_uri.find( cb_data->procedure );
//       if (iter == pmap.by_uri.end())
//       {
//         _WARN_("cannot register procedure");
//         // TODO: throw an error response
//         return;
//       }
//       iter->second->registration_id = registration_id;
//       pmap.by_id[registration_id] = iter->second;
//     }

//     _INFO_("procedure '" << cb_data->procedure << "' registered with id "
//            << registration_id );
//   }
//   else
//   {
//     _ERROR_( "ERROR: failed to process end-point registered message; no cb_data");
//   }
// }

//----------------------------------------------------------------------

// void client_service::handle_INVOCATION(ev_inbound_message* ev) // change to lowercase
// {
//   auto sp = ev->src.lock();
//   if (!sp)
//   {
//     // TODO: add handler for this situation
//     return;
//   }

//   // TODO: check, what type does WAMP allow here?

//   t_request_id reqid = ev->ja[1].as_int(); // TODO: make a helper for this, ie, json to t_requetst_id
//   int registration_id = ev->ja[2].as_int();
//   jalson::json_object & details = ev->ja[3].as_object();

//   wamp_args my_wamp_args;
//   if ( ev->ja.size() > 4 ) my_wamp_args.args_list = ev->ja[ 4 ];

//   int router_session_id = ev->user_conn_id;

//   {
//     std::unique_lock<std::mutex> guard(m_procedures_lock);
//     procedure_map& pmap = m_procedures[router_session_id];
//     auto iter = pmap.by_id.find(registration_id);

//     if (iter == pmap.by_id.end())
//     {
//       throw event_error::request_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION,
//                                        INVOCATION,
//                                        ev->ja[1].as_int());
//     }

//     auto & proc = iter->second;

//     size_t mycallid = 0;
//     bool had_exception = true;
//     {
//       // TODO: need to ensure we cannt take the 0 value, and that our valid is avail
//       std::unique_lock<std::mutex> guard(m_calls_lock);
//       mycallid = ++m_callid;
// //      m_calls[ mycallid ] . s = rkey.s;  --- looks like error?
//       m_calls[ mycallid ] . seshandle = ev->src;
//       m_calls[ mycallid ] . request_id = reqid;
// //      m_calls[ mycallid ] . internal = false;
//     }
//     // TODO: during exception, could log more details.
//     try
//     {
//       invoke_details invoke(mycallid);
//       invoke.svc = this;
//       proc->user_cb(mycallid, invoke, proc->uri,  details, my_wamp_args, ev->src, proc->user_data);
//       had_exception = false;
//     }
//     catch (const std::exception& e)
//     {
//       const char* what = e.what();
//       _WARN_("exception thrown by procedure '"<< proc->uri << "': " << (what?e.what():""));
//     }
//     catch (...)
//     {
//       _WARN_("unknown exception thrown by user procedure '"<< proc->uri << "'");
//     }

//     if (had_exception)
//     {
//       std::unique_lock<std::mutex> guard(m_calls_lock);
//       m_calls.erase( mycallid );
//     }
//   }

// }

//----------------------------------------------------------------------

// void client_service::post_reply(t_invoke_id callid,
//                                 wamp_args& the_args)
// {
//   /* user thread or EV thread */

//   call_context context;
//   {

//     std::unique_lock<std::mutex> guard(m_calls_lock);
//     auto it = m_calls.find( callid );

//     if (it != m_calls.end())
//     {
//       context = it->second;
//       m_calls.erase( it );
//     }
//     else
//     {
//       _ERROR_("unknown callid");
//       return;
//     }
//   }

//   // if ( context.internal )
//   // {
//   //   outbound_response_event* ev = new outbound_response_event();

//   //   ev->destination   = context.seshandle;;
//   //   ev->response_type = RESULT;
//   //   ev->request_type  = CALL;
//   //   ev->reqid         = context.requestid;
//   //   ev->args          = the_args;

//   //   m_evl->push( ev );
//   // }
//   // else
//   // {
//     build_message_cb_v4 msgbuilder;
//     msgbuilder = [&context,&the_args](){
//       jalson::json_array msg;
//       msg.push_back(YIELD);
//       msg.push_back(context.request_id);
//       msg.push_back(jalson::json_object());
//       if (!the_args.args_list.is_null()) msg.push_back(the_args.args_list);
//       if (!the_args.args_list.is_null() && !the_args.args_dict.is_null()) msg.push_back(the_args.args_dict);
//       return msg;
//     };
//     m_sesman->send_to_session(context.seshandle, msgbuilder);
//   // }
// }

//----------------------------------------------------------------------

// void client_service::post_error(t_invoke_id callid,
//                                 std::string& error_uri)
// {
//   /* user thread or EVL thread */

//   call_context context;
//   {
//     std::unique_lock<std::mutex> guard(m_calls_lock);
//     auto it = m_calls.find( callid );
//     if (it != m_calls.end())
//     {
//       context = it->second;
//       m_calls.erase( it );
//     }
//     else
//     {
//       _ERROR_("unknown callid");
//       return;
//     }
//   }

//   outbound_response_event* ev = new outbound_response_event();

//   ev->destination   = context.seshandle;
//   ev->response_type = ERROR;
//   ev->request_type  = INVOCATION;
//   ev->reqid         = context.request_id;
//   ev->error_uri     = error_uri;

//   m_evl->push( ev );

// }


//----------------------------------------------------------------------

void client_service::add_topic(topic* topic)
{
  // TODO: check that it is uniqyue
  std::unique_lock<std::mutex> guard(m_topics_lock);
  m_topics[ topic->uri() ] = topic;

  // observer the topic for changes, so that changes can be converted into to
  // publish messages sent to peer
  topic->add_observer(
    this,
    [this](const XXX::topic* src,
           const jalson::json_value& patch)
    {
      /* USER thread */

      size_t router_session_count = 0;
      {
        std::unique_lock<std::mutex> guard(m_router_sessions_lock);
        router_session_count = m_router_sessions.size();
      }

      if (router_session_count>0)
      {
        // TODO: legacy approach of publication, using the EV thread. Review
		    // this once topic implementation has been reviewed.
        auto sp = std::make_shared<ev_outbound_publish>(src->uri(),
                                                        patch,
                                                        router_session_count);
        {
          std::unique_lock<std::mutex> guard(m_router_sessions_lock);
          for (auto & item : m_router_sessions)
          {
            session_handle sh = item.second->handle();
            sp->targets.push_back( sh );
          }
        }
        m_evl->push( sp );
      }


      // TODO: here, I need to obtain our session to the router, so that topic
      // updates can be sent to the router, for it to the republish as events.
      // Currently we have not stored that anywhere.

      // generate an internal event destined for the embedded
      // router
      // if (m_embed_router != nullptr)
      // {
      //   ev_internal_publish* ev = new ev_internal_publish(src->uri(),
      //                                                   patch);
      //   ev->realm = m_config.realm;
      //   m_evl->push( ev );
      // }
    });
}


//----------------------------------------------------------------------


/* This was the special interface on the dealer_service API which allows CALL
 * sequences to be triggered by the API client, rather than a traditiona WAMP
 * client (ie, TCP based).  The callback is the entry point into the user code
 * when a YIELD or ERROR is received.
 */
// t_request_id client_service::call_rpc(router_conn* rs,
//                                       std::string proc_uri,
//                                       const jalson::json_object& options,
//                                       wamp_args args,
//                                       wamp_call_result_cb cb,
//                                       void* cb_user_data)
// {
//   /* USER thread */

//   session_handle sh = rs->m_internal_session_handle;
//   if (m_sesman->session_is_open(sh ) == false)
//   {
//     return 0;
//   }
//   // TODO: review this; the requst ID should be generateed on a peer session basis?

//   // TODO: this ID needs to be atomic, because there could be multiple USER threads coming in here.
//   t_client_request_id int_req_id = m_next_client_request_id++;

//   {
//     std::lock_guard<std::mutex> guard( m_pending_wamp_call_lock );
//     auto & pending = m_pending_wamp_call[int_req_id];
//     pending.user_cb = cb;
//     pending.user_data = cb_user_data;
//     pending.rpc= proc_uri;
//   }

// //   outbound_call_event * ev = new outbound_call_event();

// //   ev->dest = sh;
// // //  ev->msg_type = CALL;
// //   ev->rpc_name= proc_uri;
// //   ev->args = args; // memleak?
// //   ev->options = options;
// //   ev->internal_req_id=int_req_id;

// //   m_evl->push( ev );
//   t_request_id call_request_id = 0;

//   build_message_cb_v2 msg_builder2 = [&](t_request_id request_id)
//     {
//       call_request_id = request_id;
//       jalson::json_array msg;
//       msg.push_back( CALL );
//       msg.push_back( request_id );
//       msg.push_back( options );
//       msg.push_back( proc_uri );
//       if (!args.args_list.is_null()) msg.push_back( args.args_list );
//       if (!args.args_dict.is_null()) msg.push_back( args.args_dict );

//       return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
//                                                                 nullptr );
//     };

//   m_sesman->send_request(sh, CALL, int_req_id, msg_builder2);

//   return call_request_id;
// }


int client_service::connect_session(router_conn& rs,
                                    const std::string & addr,
                                    int port)
{
  /* USER thread */

  m_io_loop->add_connection(addr,
                            port,
                            rs.router_session_id());
  return 0;
}


// void client_service::invoke_direct(session_handle& sh,
//                                    t_request_id req_id,
//                                    int reg_id,
//                                    wamp_args& args)


// {
//   _INFO_("direct invoke");
//   auto sp = sh.lock();
//   if (!sp)
//   {
//     // TODO: add handler for this situation
//     return;
//   }

//   std::string procname;
//   {
//     std::unique_lock<std::mutex> guard(m_registrationid_map_lock2);
//     auto it = m_registrationid_map2.find(reg_id);

//     if (it == m_registrationid_map2.end())
//     {
//       // TODO: test this, ie, failure during direct CALL
//       throw event_error::request_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION,
//                                        INVOCATION, // or CALL?
//                                        req_id);
//     }
//     procname = it->second;
//   }
//   std::pair<rpc_cb,void*> rpc_actual;
//   {
//     std::unique_lock<std::mutex> guard(m_procedures_lock);
//     auto it = m_procedures.find( procname );

//     if (it == m_procedures.end())
//     {
//       throw event_error::request_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION,
//                                        INVOCATION,
//                                        req_id);
//     }
//     rpc_actual = it->second;
//   }

//   if (rpc_actual.first)
//   {
//     size_t mycallid = 0;
//     bool had_exception = true;
//     {
//       // TODO: need to ensure we cannt take the 0 value, and that our valid is avail
//       std::unique_lock<std::mutex> guard(m_calls_lock);
//       mycallid = ++m_callid;
// //      m_calls[ mycallid ] . s = rkey.s;  --- looks like error?
//       m_calls[ mycallid ] . seshandle = sh;
//       m_calls[ mycallid ] . requestid = req_id;
//       m_calls[ mycallid ] . internal  = true;
//     }
//     // TODO: during exception, could log more details.
//     try
//     {
//       jalson::json_object details;

//       invoke_details invoke(mycallid);
//       invoke.svc = this;
//       rpc_actual.first(mycallid, invoke, procname, details, args, sh, rpc_actual.second);
//       had_exception = false;
//     }
//     catch (const std::exception& e)
//     {
//       const char* what = e.what();
//       _WARN_("exception thrown by procedure '"<< procname << "': " << (what?e.what():""));
//     }
//     catch (...)
//     {
//       _WARN_("unknown exception thrown by user procedure '"<<procname << "'");
//     }

//     if (had_exception)
//     {
//       std::unique_lock<std::mutex> guard(m_calls_lock);
//       m_calls.erase( mycallid );
//     }
//   }

// }



// void client_service::handle_RESULT(ev_inbound_message* ev) // change to lowercase
// {
//   /* EV thread */

//   int reqid=ev->ja[1].as_int();
//   _INFO_("Got RESULT for reqid " << reqid << "," << ev->internal_req_id);

//   pending_wamp_call pendingreq;
//   {
//     std::lock_guard<std::mutex> guard( m_pending_wamp_call_lock );
//     pendingreq = m_pending_wamp_call[ev->internal_req_id]; // TODO: need to erase after this
//   }

//   if ( pendingreq.user_cb )
//   {
//     wamp_call_result r;
//     r.reqid = ev->internal_req_id;
//     r.procedure = pendingreq.rpc;
//     r.user = pendingreq.user_data;
//     // TODO: need parse error checking here
//     r.args.args_list  = ev->ja[3];
//     r.details = ev->ja[2].as_object();

//     try {

//       pendingreq.user_cb(std::move(r));
//     }
//     catch(...){}
//   }
//   else
//   {
//     // TODO:  improve this error
//     _ERROR_("cannot find pending request, ");
//   }
// }

// void client_service::handle_ERROR(ev_inbound_message* ev)
// {
//   int request_msg_type = jalson::get_ref(ev->ja, 1).as_int();

//   switch (request_msg_type)
//   {
//     case CALL :
//     {

//       auto & call_req = m_pending_wamp_call[ev->internal_req_id];
//       if (call_req.user_cb)
//       {
//         wamp_call_result r;
//         r.was_error = true;
//         r.error_uri = ev->ja[4].as_string();
//         r.reqid = ev->internal_req_id;
//         r.procedure = call_req.rpc;
//         r.user = call_req.user_data;
//         r.details = ev->ja[3].as_object();
//         // TODO: need parse error checking here
//         r.args.args_list  = ev->ja[5];

//         try {
//           call_req.user_cb(std::move(r));
//         }
//         catch(...){}
//         return;
//       }
//     }
//     default:
//     {
//       _WARN_("ignoring unexpection ERROR, request_msg_type=" << request_msg_type);
//       return;
//     }
//   }
//   // TODO: need to parse the INVOCATION message here, eg, check it is valid
//   RegistrationKey rkey;
//   rkey.router_session_id = ev->user_conn_id;
//   rkey.id = ev->ja[2].as_int();

//   std::string procname;
//   {
//     std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
//     auto it = m_registrationid_map.find(rkey);

//     if (it == m_registrationid_map.end())
//     {
//       throw event_error::request_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION,
//                                        INVOCATION,
//                                        ev->ja[1].as_int());
//     }
//     procname = it->second;
//   }

//   std::pair< rpc_cb,void*> rpc_actual;
//   {
//     std::unique_lock<std::mutex> guard(m_procedures_lock);
//     auto it = m_procedures.find( procname );

//     if (it == m_procedures.end())
//     {
//       throw event_error::request_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION,
//                                        INVOCATION,
//                                        ev->ja[1].as_int());
//     }
//     rpc_actual = it->second;
//   }

//   _INFO_( "invoke lookup success, key " << rkey.router_session_id <<":"<<rkey.id  << " -> " << procname );

//   wamp_args my_wamp_args;
//   if ( ev->ja.size() > 4 ) my_wamp_args.args_list = ev->ja[ 4 ];

//   t_request_id reqid = ev->ja[1].as_int(); // TODO: make a helper for this, ie, json to t_requetst_id

//   if (rpc_actual.first)
//   {
//     size_t mycallid = 0;
//     bool had_exception = true;
//     {
//       // TODO: need to ensure we cannt take the 0 value, and that our valid is avail
//       std::unique_lock<std::mutex> guard(m_calls_lock);
//       mycallid = ++m_callid;
// //      m_calls[ mycallid ] . s = rkey.s;  --- looks like error?
//       m_calls[ mycallid ] . seshandle = ev->src;
//       m_calls[ mycallid ] . requestid = reqid;
//       m_calls[ mycallid ] . internal = false;
//     }
//     // TODO: during exception, could log more details.
//     try
//     {
//       jalson::json_object details;
//       rpc_actual.first(mycallid, procname, details, my_wamp_args, ev->src, rpc_actual.second);
//       had_exception = false;
//     }
//     catch (const std::exception& e)
//     {
//       const char* what = e.what();
//       _WARN_("exception thrown by procedure '"<< procname << "': " << (what?e.what():""));
//     }
//     catch (...)
//     {
//       _WARN_("unknown exception thrown by user procedure '"<<procname << "'");
//     }

//     if (had_exception)
//     {
//       std::unique_lock<std::mutex> guard(m_calls_lock);
//       m_calls.erase( mycallid );
//     }
//   }

//   return;
// }

//----------------------------------------------------------------------

// t_request_id client_service::subscribe_remote_topic(router_conn* rs,
//                                                     const std::string& uri,
//                                                     const jalson::json_object& options,
//                                                     subscription_cb cb,
//                                                     void * user)
// {
//   session_handle sh = rs->m_internal_session_handle;
//   if (m_sesman->session_is_open(sh ) == false)
//   {
//     return 0;  // TODO: how to convery this immedaite failyre back to caller?  Smae for RPC too
//   }

//   t_client_request_id int_req_id = 0;
//   // TODO: maybe later, upgrade this to use an internal client request ID?
//   {
//     std::unique_lock<std::mutex> guard(m_subscriptions_lock);

//     // TODO: what is C++11 idiom for direct insertion, using perfect forwarding?
//     subscription subs;
//     subs.sh        = sh;
//     subs.uri       = uri;
//     subs.user_cb   = cb;
//     subs.user_data = user;
//     subs.router_session_idxx = rs->router_session_id(); // TODO: what is this used for?

//     int_req_id = m_subscription_req_id++;
//     m_pending_wamp_subscribe[int_req_id] = subs;
//   }

//   // ev_outbound_subscribe* ev = new ev_outbound_subscribe(uri, options);
//   // ev->internal_req_id = int_req_id;
//   // ev->dest = sh;
//   // m_evl->push( ev );

//   t_request_id subscribe_request_id = 0;
//   build_message_cb_v2 msg_builder2 = [&](t_request_id request_id)
//     {
//       subscribe_request_id = request_id;
//       jalson::json_array msg;
//       msg.push_back( SUBSCRIBE );
//       msg.push_back( request_id );
//       msg.push_back( options );
//       msg.push_back( uri );

//       return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
//                                                                 nullptr );
//     };

//   m_sesman->send_request(sh, SUBSCRIBE, int_req_id, msg_builder2);

//   return subscribe_request_id;
// }

// void client_service::handle_SUBSCRIBED(ev_inbound_subscribed* ev)
// {
//   /* EV thread */

//   // get session id
//   auto sp = ev->src.lock();
//   if (!sp) return;
//   t_sid sid = *sp;

//   // get subscription id
//   size_t subscrid =  ev->ja[2].as_uint();


//   subscription temp;
//   std::cout << "got subscribed event, " << ev->internal_req_id << ", subscription id " <<subscrid <<  "\n";

//   {
//     std::unique_lock<std::mutex> guard(m_subscriptions_lock);

//     auto pendit = m_pending_wamp_subscribe.find(ev->internal_req_id);
//     if (pendit == m_pending_wamp_subscribe.end())
//     {
//       _WARN_("Ingoring SUBSCRIBED event; cannot find original request");
//       return;
//     }

//     temp = pendit->second;
//     m_pending_wamp_subscribe.erase(pendit);

//     auto & subs_for_session = m_subscriptions[ sid ];
//     subs_for_session[ subscrid ] = temp;
//   }

//   // user callback
//   try {
//     temp.user_cb(XXX::e_sub_start,
//                  temp.uri,
//                  jalson::json_object(),
//                  jalson::json_array(),
//                  jalson::json_object(),
//                  temp.user_data);
//   } catch (...) {}
// }


// void client_service::handle_EVENT(ev_inbound_message* ev)
// {
//   /* EV thread */

//   size_t subscrid  = ev->ja.at(1).as_uint();
// //  size_t publishid = ev->ja.at(2).as_uint();
//   jalson::json_object & details = ev->ja.at(3).as_object();
//   jalson::json_value * ptr_args_list = jalson::get_ptr(ev->ja, 4); // optional
//   jalson::json_value * ptr_args_dict = jalson::get_ptr(ev->ja, 5); // optional

//   const jalson::json_array  & args_list = ptr_args_list? ptr_args_list->as_array()  : jalson::json_array();
//   const jalson::json_object & args_dict = ptr_args_dict? ptr_args_dict->as_object() : jalson::json_object();

//   session_handle src = ev->src;
//   if (auto sp = src.lock())
//   {
//     t_sid sid = *sp;

//     auto iter = m_subscriptions.find( sid );
//     if (iter == m_subscriptions.end())
//     {
//       _WARN_("ignoring topic event, no subscriptions for session");
//       return;
//     }

//     auto iter2 = iter->second.find( subscrid );
//     if (iter2 == iter->second.end())
//     {
//       _WARN_("ignoring topic event, subscription not found, subscription id " << subscrid);
//       return;
//     }

//     subscription& my_subscription = iter2->second;

//     try {
//       my_subscription.user_cb(e_sub_update,
//                               my_subscription.uri,
//                               details,
//                               args_list,
//                               args_dict,
//                               my_subscription.user_data);
//     } catch (...){}

//   }
// }


bool client_service::is_open(const router_conn* rs) const
{
  return m_sesman->session_is_open( rs->m_internal_session_handle );
}

void client_service::handle_event(ev_router_session_connect_fail* ev)
{
  /* EV thread */
  const t_connection_id router_session_id = ev->user_conn_id;

  std::unique_lock<std::mutex> guard(m_router_sessions_lock);

  auto iter = m_router_sessions.find( router_session_id );
  if (iter != m_router_sessions.end())
  {
    router_conn * rs = iter->second;
    if (rs->m_connection_cb)
      try {
        rs->m_connection_cb(rs, ev->status, false);
      }
      catch (...){}
  }
}

t_connection_id client_service::register_session(router_conn& rs)
{
  /* USER thread */

  std::unique_lock<std::mutex> guard(m_router_sessions_lock);
  t_connection_id id = m_next_router_session_id++;
  m_router_sessions[ id ] = &rs;

  return id;
}

// t_request_id client_service::register_procedure_impl(router_conn* rconn,
//                                                      const std::string& uri,
//                                                      const jalson::json_object& options,
//                                                      rpc_cb user_cb,
//                                                      void * user_data)
// {
//   // TODO: need to check for duplicates

//   {
//     // TODO: if possible, remove this, and only do the locking on the inbound
//     // thread, to avoid deadlock situbation if user calls register during current an invocation callback
//     std::unique_lock<std::mutex> guard(m_procedures_lock);

//     auto sp = std::make_shared<user_procedure>(uri, user_cb, user_data);
//     procedure_map& pmap = m_procedures[ rconn->m_router_session_id ];
//     pmap.by_uri[ uri ] = sp;
//   }

//   t_request_id register_request_id = 0;

//   build_message_cb_v2 msg_builder2 = [&](t_request_id request_id)
//     {
//       register_request_id = request_id;

//       jalson::json_array msg;
//       msg.push_back( REGISTER );
//       msg.push_back( request_id );
//       msg.push_back( options );
//       msg.push_back( uri );

//       Request_Register_CD_Data * cb_data = new Request_Register_CD_Data(); // TODO: memleak?
//       cb_data->procedure = uri;

//       // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
//       return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
//                                                                 cb_data );
//     };

//   // TODO: instead of 0, need to have a valie intenral request id
//   m_sesman->send_request(rconn->handle(), REGISTER, 0, msg_builder2);

//   return register_request_id;
// }

router_conn::router_conn(client_service * __svc,
                         router_session_connect_cb __cb,
                         void * __user)
  : user(__user),
    m_svc(__svc),
    m_connection_cb(__cb),
    m_router_session_id( __svc->register_session( *this ) )
{
}

int router_conn::connect(const std::string & addr, int port)
{
  return m_svc->connect_session(*this, addr, port);
}


t_request_id router_conn::call(std::string uri,
                               const jalson::json_object& options,
                               wamp_args args,
                               wamp_call_result_cb user_cb,
                               void* user_data)
{
  if (m_session)
    return m_session->call(uri, options, args, user_cb, user_data);
  else
    return 0;
}

t_request_id router_conn::subscribe(const std::string& uri,
                                    const jalson::json_object& options,
                                    subscription_cb user_cb,
                                    void * user_data)
{
  if (m_session)
    return m_session->subscribe(uri, options, user_cb, user_data);
  else
    return 0;
}


t_request_id router_conn::publish(const std::string& uri,
                                  const jalson::json_object& options,
                                  wamp_args args)
{
  if (m_session)
    return m_session->publish(uri, options, args);
  else
    return 0;
}

// t_request_id router_conn::provide(const std::string& uri,
//                                   const jalson::json_object& options,
//                                   rpc_cb user_cb,
//                                   void * user_data)
// {

//   // TODO: need to check for duplicates

//   {
//     // TODO: if possible, remove this, and only do the locking on the inbound
//     // thread, to avoid deadlock situbation if user calls register during current an invocation callback
//     std::unique_lock<std::mutex> guard(m_procedures_lock);

//     auto sp = std::make_shared<user_procedure>(uri, user_cb, user_data);
//     m_procedures.by_uri[ uri ] = sp;
//   }

//   t_request_id register_request_id = 0;

//  build_message_cb_v2 msg_builder2 = [&](t_request_id request_id)
//     {
//       register_request_id = request_id;

//       jalson::json_array msg;
//       msg.push_back( REGISTER );
//       msg.push_back( request_id );
//       msg.push_back( options );
//       msg.push_back( uri );

//       Request_Register_CD_Data * cb_data = new Request_Register_CD_Data(); // TODO: memleak?
//       cb_data->procedure = uri;

//       // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
//       return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
//                                                                 cb_data );
//     };

//   // TODO: instead of 0, need to have a valie intenral request id
//   m_svc->get_session_man()->send_request(handle(), REGISTER, 0, msg_builder2);

//   return register_request_id;

// //  return m_svc->register_procedure_impl(this, uri, options, cb, data);
// }

// void client_service::publish_all(//bool include_internal,
//                                  const std::string& uri,
//                                  const jalson::json_object& opts,
//                                  const jalson::json_array& args_list,
//                                  const jalson::json_object& args_dict)
// {
//   // publish to all connected router
//   {
//     std::unique_lock<std::mutex> guard(m_router_sessions_lock);
//     if (m_router_sessions.size()>0)
//     {
//       auto sp = std::make_shared<ev_outbound_publish>(
//         uri,
//         opts,
//         args_list,
//         args_dict,
//         m_router_sessions.size()) ;

//       for (auto & item : m_router_sessions)
//         sp->targets.push_back( item.second->handle() );

//       m_evl->push( sp );
//     }
//   }

//   // // publish to internal router
//   // if (include_internal && m_embed_router != nullptr)
//   // {
//   //   //       ev_internal_publish* ev = new ev_internal_publish(true,
//   //   //                                                       src->uri(),
//   //   //                                                       patch);
//   //   //       ev->realm = m_config.realm;
//   //   //       m_evl->push( ev );
//   // }

// }


// t_request_id client_service::publish(router_conn* rs,
//                                      const std::string& uri,
//                                      const jalson::json_object& options,
//                                      wamp_args wargs)
// {


  // session_handle sh = rs->m_internal_session_handle;
  // if (m_sesman->session_is_open(sh ) == false)
  // {
  //   return 0;
  // }

  // // // publish to all connected router
  // // auto sp = std::make_shared<ev_outbound_publish>(
  // //   uri,
  // //   opts,
  // //   args_list,
  // //   args_dict,
  // //   1);

  // // sp->targets.push_back( sh );

  // // m_evl->push( sp );

  // t_client_request_id int_req_id = m_next_client_request_id++;
  // t_request_id publish_request_id = 0;

  // build_message_cb_v2 msg_builder2 = [&](t_request_id request_id)
  //   {
  //     publish_request_id = request_id;
  //     jalson::json_array msg;
  //     msg.push_back( PUBLISH );
  //     msg.push_back( request_id );
  //     msg.push_back( options );
  //     msg.push_back( uri );
  //     if (!wargs.args_list.is_null()) msg.push_back( wargs.args_list );
  //     if (!wargs.args_dict.is_null()) msg.push_back( wargs.args_dict );

  //     return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
  //                                                               nullptr );
  //   };

  // m_sesman->send_request(sh, PUBLISH, int_req_id, msg_builder2);

  // return publish_request_id;
// }

  Logger * client_service::get_logger() { return __logptr; }
  IOLoop* client_service::get_ioloop() { return m_io_loop.get(); }
  event_loop* client_service::get_event_loop() { return m_evl.get(); }
  SessionMan* client_service::get_session_man() { return m_sesman.get(); }


t_request_id router_conn::provide(const std::string& uri,
                                  const jalson::json_object& options,
                                  rpc_cb user_cb,
                                  void * user_data)
{
  if (m_session)
    return m_session->provide(uri, options, user_cb, user_data);
  else
    return 0;
}


} // namespace XXX
