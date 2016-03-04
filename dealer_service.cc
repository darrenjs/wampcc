#include "dealer_service.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "event.h"
#include "Logger.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"

#include <unistd.h>
#include <string.h>

namespace XXX {


dealer_service::dealer_service(Logger *logptr,
                               dealer_listener* l)
  : __logptr( logptr ),
    m_io_loop( new IOLoop( logptr)),
    m_evl( new event_loop( logptr ) ),
  m_sesman( new SessionMan(logptr, *m_evl.get()) ),
  m_rpcman( new rpc_man(logptr, *m_evl.get(), [this](const rpc_details*r){this->rpc_registered_cb(r); }) ),
    m_listener( l ),
    m_next_internal_request_id(1)
{
  m_evl->set_session_man( m_sesman.get() );
  m_evl->set_rpc_man( m_rpcman.get() );

  m_evl->set_handler(YIELD,
                    [this](class event* ev){ this->handle_YIELD(ev); } );


  m_io_loop->m_new_client_cb = [this](IOHandle *h,
                                      int  status,
                                      tcp_connect_attempt_cb user_cb,
                                      void* user_data)
    {

      /* === Called on IO thread === */
      tcp_connect_event * ev = new tcp_connect_event(user_cb, user_data, status);
      if (h)
      {
        Session* sptr = m_sesman -> create_session(h, true);
        ev->src = sptr->handle();
      }
      m_evl->push( ev );
    };
}

dealer_service::~dealer_service()
{
  m_io_loop->stop();
  m_evl->stop();
}

//----------------------------------------------------------------------


void dealer_service::start()
{

  // NOTE:  not using idler anymore, because it causes 100% CPU
  // uv_idle_t idler;
  // uv_idle_init(loop, &idler);
  // uv_idle_start(&idler, io_on_idle);



  // uv_timer_t timer_req;  // TODO: should be a member?
  // uv_timer_init(loop, &timer_req);
  // timer_req.data = this;
  // uv_timer_start(&timer_req, __io_on_timer, 30000, 30000);

  // returns immediately
  m_io_loop->start();
}


// TODO: the whole connector business should be in a separate object
void dealer_service::connect(const std::string & addr,
                             int port,
                             tcp_connect_attempt_cb user_cb,
                             void* user_data)
{
  m_io_loop->add_connection(addr,
                           port,
                           user_cb,
                           user_data);
}


/* This is the special interface on the dealer_service API which allows CALL
 * sequences to be triggered by the API client, rather than a traditiona WAMP
 * client (ie, TCP based).  The callback is the entry point into the user code
 * when a YIELD or ERROR is received.
 */
unsigned int dealer_service::call_rpc(std::string rpc,
                                      call_user_cb cb,
                                      rpc_args args,
                                      void* cb_user_data)
{
  /* USER-THREAD */

  unsigned int int_req_id = m_next_internal_request_id++;

  {
    std::lock_guard<std::mutex> guard( m_pending_requests_lock );
    auto & pending = m_pending_requests[int_req_id];
    pending.cb = cb;
    pending.user_cb_data = cb_user_data;
  }

  outbound_call_event * ev = new outbound_call_event();

  ev->mode = event::eOutbound;
  ev->msg_type = CALL;
  ev->rpc_name= rpc;
  ev->cb = cb;  // memleak?
  ev->args = args; // memleak?
  ev->cb_user_data = cb_user_data;
  ev->internal_req_id=int_req_id;

  m_evl->push( ev );


  return int_req_id;
}

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



} // namespace
