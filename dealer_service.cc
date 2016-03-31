#include "dealer_service.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "pubsub_man.h"
#include "event.h"
#include "Logger.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"

#include <unistd.h>
#include <string.h>

namespace XXX {

dealer_service::dealer_service(Logger *logptr,
                               dealer_listener* l,
                               IOLoop* ext_ioloop,
                               event_loop* ext_event_loop)
  : __logptr( logptr ),
    m_io_loop( ext_ioloop? ext_ioloop : new IOLoop( logptr)),
    m_evl( ext_event_loop? ext_event_loop : new event_loop( logptr ) ),
    m_own_io(ext_ioloop == nullptr),
    m_own_ev(ext_event_loop == nullptr),
    m_sesman( new SessionMan(logptr, *m_evl) ),
    m_rpcman( new rpc_man(logptr, *m_evl, [this](const rpc_details*r){this->rpc_registered_cb(r); }) ),
    m_pubsub(new pubsub_man(logptr, *m_evl, *m_sesman)),
    m_listener( l ),
    m_next_internal_request_id(1)
{
  m_evl->set_session_man( m_sesman.get() );
  m_evl->set_rpc_man( m_rpcman.get() );
  m_evl->set_pubsub_man( m_pubsub.get() );

  m_evl->set_handler(YIELD,
                    [this](class event* ev){ this->handle_YIELD(ev); } );

  m_evl->set_handler(SUBSCRIBE,
                    [this](class event* ev){ this->handle_SUBSCRIBE(ev); } );



  // m_io_loop->m_new_client_cb = [this](IOHandle *h,
  //                                     int  status,
  //                                     tcp_connect_attempt_cb user_cb,
  //                                     void* user_data)
  //   {

  //     /* === Called on IO thread === */
  //     tcp_connect_event * ev = new tcp_connect_event(user_cb, user_data, status);
  //     if (h)
  //     {
  //       Session* sptr = m_sesman -> create_session(h, true);
  //       ev->src = sptr->handle();
  //     }
  //     m_evl->push( ev );
  //   };
}

dealer_service::~dealer_service()
{
  if (m_own_io) m_io_loop->stop();
  if (m_own_ev) m_evl->stop();

  if (m_own_io) delete m_io_loop;
  if (m_own_ev) delete m_evl;
}

//----------------------------------------------------------------------


void dealer_service::start()
{
  // returns immediately
  if (m_own_io) m_io_loop->start();
}


// // TODO: the whole connector business should be in a separate object
// void dealer_service::connect(const std::string & addr,
//                              int port,
//                              tcp_connect_attempt_cb user_cb,
//                              void* user_data)
// {
//   m_io_loop->add_connection(addr,
//                            port,
//                            user_cb,
//                            user_data);
// }


// /* This is the special interface on the dealer_service API which allows CALL
//  * sequences to be triggered by the API client, rather than a traditiona WAMP
//  * client (ie, TCP based).  The callback is the entry point into the user code
//  * when a YIELD or ERROR is received.
//  */
// unsigned int dealer_service::call_rpc(std::string rpc,
//                                       call_user_cb cb,
//                                       rpc_args args,
//                                       void* cb_user_data)
// {
//   /* USER-THREAD */

//   unsigned int int_req_id = m_next_internal_request_id++;

//   {
//     std::lock_guard<std::mutex> guard( m_pending_requests_lock );
//     auto & pending = m_pending_requests[int_req_id];
//     pending.cb = cb;
//     pending.user_cb_data = cb_user_data;
//   }

//   outbound_call_event * ev = new outbound_call_event();

//   ev->mode = event::eOutbound;
//   ev->msg_type = CALL;
//   ev->rpc_name= rpc;
//   ev->cb = cb;  // memleak?
//   ev->args = args; // memleak?
//   ev->cb_user_data = cb_user_data;
//   ev->internal_req_id=int_req_id;

//   m_evl->push( ev );


//   return int_req_id;
// }

//----------------------------------------------------------------------

void dealer_service::rpc_registered_cb(const rpc_details* ev)
{
  if (m_listener) m_listener->rpc_registered( ev->uri );
}

//----------------------------------------------------------------------

void dealer_service::handle_YIELD(event* ev)
{
  unsigned int internal_req_id = ev->internal_req_id;
//  void * user = ev->user;

  pending_request pend ;

  {
    std::lock_guard<std::mutex> guard( m_pending_requests_lock );
    pend = m_pending_requests[internal_req_id];
  }

  call_info info;
  info.reqid = ev->ja[1].as_uint();
  info.procedure = pend.procedure;

  rpc_args args;
  args.args    = ev->ja[3]; // dont care about the type
  args.options = ev->ja[2].as_object();  // TODO: need to pre-verify the message


  // TODO: catch and log exception
  if ( pend.cb )
  {
    try
    {
      pend.cb(info, args, pend.user_cb_data);
    }
    // TODO: try to print
    catch (...)
    {
      _WARN_("exception during user callback");
    }

  }
  else
  {
    _WARN_("no callback function to handle request response");
  }

}

void dealer_service::listen(int port)
{
  m_io_loop->add_server(
    port,
    [this](int /* port */,
           IOHandle* hndl)
    {
      m_sesman->create_session(hndl,true, nullptr, nullptr);
    } );
}

int dealer_service::register_procedure(std::string uri)
{
  return m_rpcman->register_internal_rpc(uri);
}

//----------------------------------------------------------------------

void dealer_service::handle_SUBSCRIBE(event* ev)
{
  m_pubsub->handle_subscribe(ev);
}


} // namespace
