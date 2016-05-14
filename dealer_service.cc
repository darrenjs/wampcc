#include "dealer_service.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "pubsub_man.h"
#include "Callbacks.h"
#include "event.h"
#include "Logger.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"
#include "client_service.h"

#include <unistd.h>
#include <string.h>

namespace XXX {

dealer_service::dealer_service(client_service * __svc, dealer_listener* l)
  :__logptr(__svc->get_logger()),
   m_io_loop(__svc->get_ioloop()),
   m_evl(__svc->get_event_loop()),
   m_own_io(false),
   m_own_ev(false),
   m_sesman( new SessionMan(__logptr, *m_evl) ),
   m_rpcman( new rpc_man(__logptr, [this](const rpc_details&r){this->rpc_registered_cb(r); })),
   m_pubsub(new pubsub_man(__logptr, *m_evl, *m_sesman)),
   m_listener( l ),
   m_next_internal_request_id(1)
{
  m_evl->set_session_man( m_sesman.get() );
  m_evl->set_pubsub_man( m_pubsub.get() );
};


dealer_service::~dealer_service()
{
  if (m_own_io) m_io_loop->stop();
  if (m_own_ev) m_evl->stop();

  if (m_own_io) delete m_io_loop;
  if (m_own_ev) delete m_evl;
}


void dealer_service::rpc_registered_cb(const rpc_details& r)
{
  if (m_listener) m_listener->rpc_registered( r.uri );
}

//----------------------------------------------------------------------

// /* TODO: the way the handlers are set up, as callback via functional objects,
//  * means I have to pass in the base class 'event', even though earlier in the
//  * call sequence I would have detected a YIELD and corresponding type as
//  * ev_inbound_message.
//  */
// void dealer_service::handle_YIELD(ev_inbound_message* ev)
// {
//   // TODO: use a proper int type
//   unsigned int internal_req_id = ev->internal_req_id;

//   pending_request pend ;
//   {
//     std::lock_guard<std::mutex> guard( m_pending_requests_lock );
//     pend = m_pending_requests[internal_req_id];
//     // TODO: if found, remove it.  If not found, cannot continue
//   }

//   if (pend.is_external )
//   {
//     // send a RESULT back to originator of the call
//     build_message_cb_v4 msgbuilder;
//     msgbuilder = [&pend, &ev](){
//       jalson::json_array msg;
//       msg.push_back(RESULT);
//       msg.push_back(pend.call_request_id);
//       msg.push_back(jalson::json_object());
//       auto ptr = jalson::get_ptr(ev->ja,3);
//       if (ptr) msg.push_back(*ptr);
//       ptr = jalson::get_ptr(ev->ja,4);
//       if (ptr) msg.push_back(*ptr);
//       return msg;
//     };
//     m_sesman->send_to_session(pend.call_source, msgbuilder);
//     return;
//   }
//   else
//   {

//     if ( pend.cb )
//     {
//       wamp_call_result r;

//       //    call_info info;
//       r.reqid = ev->ja[1].as_uint();
//       r.procedure = pend.procedure;
//       r.details = ev->ja[2].as_object();
//       r.args.args_list = ev->ja[3]; // dont care about the type
//       r.user = pend.user_cb_data;
//       try {
//         pend.cb(std::move(r));
//       }
//       catch (...) { }
//     }
//     else
//     {
//       _WARN_("no callback function to handle request response");
//     }
//   }

// }

void dealer_service::listen(int port)
{
  m_io_loop->add_server(
    port,
    [this](int /* port */,
           IOHandle* hndl)
    {
      // note, we dont make use of the user connection id for passive sessions
      Session* sptr = m_sesman->create_session(hndl, true, t_connection_id(), "" /* undefined realm */);

      auto handlers = server_msg_handler();

      handlers.handle_call  = [this](Session* s, std::string u, jalson::json_array & m, wamp_invocation_reply_fn f) {
        return this->handle_call(s,u,m,f);
      };

      handlers.handle_inbound_publish  = [this](Session* sptr, std::string uri, jalson::json_array & msg ) {
        m_pubsub->inbound_publish(sptr->realm(), uri, msg);
      };

      handlers.inbound_subscribe  = [this](Session* sptr, jalson::json_array & msg) {
        m_pubsub->handle_inbound_subscribe(sptr, msg);
      };

      handlers.inbound_register  = [this](Session* sptr, std::string uri, registered_fn fn) {
        m_rpcman->handle_inbound_register(sptr, uri, fn);
      };

      sptr->set_server_handler( std::move(handlers) );
    } );
}


void dealer_service::register_procedure(const std::string& realm,
                                        const std::string& uri,
                                        const jalson::json_object& options,
                                        rpc_cb user_cb,
                                        void * user_data)
{


  m_rpcman->register_internal_rpc_2(realm, uri, options, user_cb, user_data);
}


// void dealer_service::invoke_procedure(rpc_details& rpc,
//                                       ev_inbound_message* ev)
// {
//   t_request_id request_id = ev->ja[1].as_int();
//   wamp_args my_wamp_args;
//   if ( ev->ja.size() > 4 ) my_wamp_args.args_list = ev->ja[ 4 ].as_array();
//   _INFO_("got internal RPC call request");

//   size_t mycallid = 0;
// //  bool had_exception = true;

//   {
//     std::unique_lock<std::mutex> guard(m_calls_lock);
//     mycallid = m_next_call_id++;
//     m_calls[ mycallid ].seshandle = ev->src;
//     m_calls[ mycallid ].requestid = request_id;
//   }


//   // TODO: note this is the new style of intenral RPC callback
//   if (rpc.user_cb)
//   {
//     invoke_details invoke(mycallid);
//     invoke.reply_fn = [this](t_request_id tid, wamp_args& args){
//       this->reply(tid, args, false, "");
//     };
//     jalson::json_object details;

//     // TODO: handle exception (raises an ERROR)
//     try
//     {
//       rpc.user_cb(mycallid,
//                   invoke,
//                   rpc.uri,
//                   details,
//                   my_wamp_args,
//                   ev->src,
//                   rpc.user_data);
//     }
//     catch (XXX::invocation_exception& ex)
//     {
//       this->reply(mycallid, ex.args(), true, ex.what());
//     }
//     catch (std::exception& ex)
//     {
//       wamp_args temp;
//       this->reply(mycallid, temp, true, ex.what());
//     }
//     catch (...)
//     {
//       wamp_args temp;
//       this->reply(mycallid, temp, true, WAMP_RUNTIME_ERROR);
//     }
//   }
// }


bool dealer_service::reply(t_invoke_id callid,
                           wamp_args& the_args,
                           bool is_error,
                           std::string error_uri)
{
  proc_invoke_context context;
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
      return false;
    }
  }

  build_message_cb_v4 msgbuilder;
  msgbuilder = [&](){
    jalson::json_array msg;

    if (is_error)
    {
      msg.push_back(ERROR);
      msg.push_back(CALL);
      msg.push_back(context.requestid);
      msg.push_back(jalson::json_object());
      msg.push_back(std::move(error_uri));
    }
    else
    {
      msg.push_back(RESULT);
      msg.push_back(context.requestid);
      msg.push_back(jalson::json_object());
    }
    if (!the_args.args_list.is_null()) msg.push_back(the_args.args_list);
    if (!the_args.args_dict.is_null()) msg.push_back(the_args.args_dict);
    return msg;
  };
  m_sesman->send_to_session(context.seshandle, msgbuilder);
  return true;
}


t_request_id dealer_service::publish(const std::string& topic,
                                     const std::string& realm,
                                     const jalson::json_object& options,
                                     wamp_args args)
{
  /* USER thread */
  return m_pubsub->publish(topic, realm, options, std::move(args));
}



t_request_id dealer_service::handle_call(Session* sptr,
                                         const std::string&,
                                         jalson::json_array & msg,
                                         wamp_invocation_reply_fn fn )
{
  /* EV thread */
  std::cout << "dealer_service::handle_call" << "\n";

  // TODO: improve json parsing
  t_request_id request_id = msg[1].as_int();
  std::string uri = msg[3].as_string();

  // TODO: use direct lookup here, instead of that call to public function, wheich can then be deprecated
  rpc_details rpc = m_rpcman->get_rpc_details(uri, sptr->realm());
  if (rpc.registration_id)
  {
    wamp_args my_wamp_args;
    if ( msg.size() > 4 ) my_wamp_args.args_list = msg[ 4 ].as_array();
    if ( msg.size() > 5 ) my_wamp_args.args_list = msg[ 4 ].as_object();


    _INFO_("handle_call: found the PROC");
    if (rpc.type == rpc_details::eInternal)
    {
      _INFO_("got internal RPC call request");

      size_t mycallid = 0;
      {
        std::unique_lock<std::mutex> guard(m_calls_lock);
        mycallid = m_next_call_id++;
        m_calls[ mycallid ].seshandle = sptr->handle();
        m_calls[ mycallid ].requestid = request_id;
      }

      // TODO: note this is the new style of intenral RPC callback
      if (rpc.user_cb)
      {
        invoke_details invoke(mycallid);
        invoke.reply_fn = [this](t_request_id tid, wamp_args& args){
          this->reply(tid, args, false, "");
        };
        jalson::json_object details;

        try
        {
          session_handle h = sptr->handle();
          rpc.user_cb(mycallid, invoke, rpc.uri, details, my_wamp_args, h, rpc.user_data);
        }
        catch (XXX::invocation_exception& ex)
        {
          this->reply(mycallid, ex.args(), true, ex.what());
        }
        catch (std::exception& ex)
        {
          wamp_args temp;
          this->reply(mycallid, temp, true, ex.what());
        }
        catch (...)
        {
          wamp_args temp;
          this->reply(mycallid, temp, true, WAMP_RUNTIME_ERROR);
        }
        return 0;
      }


    }

    else
    {
      unsigned int internal_req_id = m_next_internal_request_id++;
      {
        std::lock_guard<std::mutex> guard( m_pending_requests_lock );
        auto & pending = m_pending_requests[internal_req_id];
        pending.is_external = true;
        pending.call_request_id = request_id;
        pending.call_source = sptr->handle();
      }

      Session* sptr = m_sesman->get_session(rpc.sesionh);
      // t_request_id invocation_request_id =
      sptr->invocation(rpc.registration_id,
                       jalson::json_object(),
                       my_wamp_args,
                       fn);
    }
  }

  else
  {
    _WARN_("Failed to find RPC for CALL request: " << sptr->realm() << "::" << rpc.uri);
    // TODO : test this path; should reulst in a ERROR going back to the
    // client process, and that it can successfully handle it.
    throw event_error(WAMP_ERROR_URI_NO_SUCH_PROCEDURE);
  }

  return request_id;
}

} // namespace
