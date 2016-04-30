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
                               event_loop* ext_event_loop,
                               internal_invoke_cb internal_rpc_cb)
  : __logptr( logptr ),
    m_io_loop( ext_ioloop? ext_ioloop : new IOLoop( logptr)),
    m_evl( ext_event_loop? ext_event_loop : new event_loop( logptr ) ),
    m_own_io(ext_ioloop == nullptr),
    m_own_ev(ext_event_loop == nullptr),
    m_sesman( new SessionMan(logptr, *m_evl) ),
    m_rpcman( new rpc_man(logptr, *m_evl, [this](const rpc_details&r){this->rpc_registered_cb(r); })),
    m_pubsub(new pubsub_man(logptr, *m_evl, *m_sesman)),
    m_internal_invoke_cb(internal_rpc_cb),
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

  m_evl->set_handler2(CALL,
                    [this](ev_inbound_message* ev){ this->handle_CALL(ev); } );

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


void dealer_service::rpc_registered_cb(const rpc_details& r)
{
  if (m_listener) m_listener->rpc_registered( r.uri );
}

//----------------------------------------------------------------------

/* TODO: the way the handlers are set up, as callback via functional objects,
 * means I have to pass in the base class 'event', even though earlier in the
 * call sequence I would have detected a YIELD and corresponding type as
 * ev_inbound_message.
 */
void dealer_service::handle_YIELD(event* ev)
{
  ev_inbound_message * ev2 = dynamic_cast<ev_inbound_message *>(ev);
  if (ev2)
  {
    // TODO: use a proper int type
    unsigned int internal_req_id = ev2->internal_req_id;

    pending_request pend ;
    {
      std::lock_guard<std::mutex> guard( m_pending_requests_lock );
      pend = m_pending_requests[internal_req_id];
      // TODO: if found, remove it.  If not found, cannot continue
    }

    if (pend.is_external )
    {
      // send a RESULT back to originator of the call
      build_message_cb_v4 msgbuilder;
      msgbuilder = [&pend, &ev2](){
        jalson::json_array msg;
        msg.push_back(RESULT);
        msg.push_back(pend.call_request_id);
        msg.push_back(jalson::json_object());
        auto ptr = jalson::get_ptr(ev2->ja,3);
        if (ptr) msg.push_back(*ptr);
        ptr = jalson::get_ptr(ev2->ja,4);
        if (ptr) msg.push_back(*ptr);
        return msg;
      };
      m_sesman->send_to_session(pend.call_source, msgbuilder);
      return;
    }
    else
    {
      call_info info;
      info.reqid = ev2->ja[1].as_uint();
      info.procedure = pend.procedure;

      jalson::json_object details = ev2->ja[2].as_object();
      wamp_args args;
      args.args_list = ev2->ja[3]; // dont care about the type

      if ( pend.cb )
      {
        try {
          pend.cb(info, details, args, pend.user_cb_data);
        }
        catch (...) { }
      }
      else
      {
        _WARN_("no callback function to handle request response");
      }
    }
  }
}

void dealer_service::listen(int port)
{
  m_io_loop->add_server(
    port,
    [this](int /* port */,
           IOHandle* hndl)
    {
      // note, we dont make use of the user connection id for passive sessions
      m_sesman->create_session(hndl, true, t_connection_id(), "" /* undefined realm */);
    } );
}

int dealer_service::register_internal_procedure(std::string uri,
                                                const std::string& realm)
{
  return m_rpcman->register_internal_rpc(uri, realm);
}

//----------------------------------------------------------------------

void dealer_service::handle_SUBSCRIBE(event* ev)
{
  ev_inbound_message * ev2 = dynamic_cast<ev_inbound_message *>(ev);
  if (ev2)
  {
    m_pubsub->handle_subscribe(ev2);
  }
}


void dealer_service::handle_CALL(ev_inbound_message* ev)
{
  // TODO: improve json parsing
  int call_request_id = ev->ja[1].as_int();
  std::string uri = ev->ja[3].as_string();

  // TODO: use direct lookup here, instead of that call to public function, wheich can then be deprecated
  rpc_details rpc = m_rpcman->get_rpc_details(uri, ev->realm);
  if (rpc.registration_id)
  {
    if (rpc.type == rpc_details::eInternal)
    {

      if (m_internal_invoke_cb)
      {
        t_request_id reqid = ev->ja[1].as_int();
        wamp_args my_wamp_args;

        if ( ev->ja.size() > 4 ) my_wamp_args.args_list = ev->ja[ 4 ].as_array();
        m_internal_invoke_cb( ev->src,
                              reqid,
                              rpc.registration_id,
                              my_wamp_args);
      }
    }
    else
    {
      unsigned int internal_req_id = m_next_internal_request_id++;
      {
        std::lock_guard<std::mutex> guard( m_pending_requests_lock );
        auto & pending = m_pending_requests[internal_req_id];
        pending.is_external = true;
        pending.call_request_id = call_request_id;
        pending.call_source = ev->src;
      }

      build_message_cb_v2 msg_builder2 = [&](int request_id)
        {
          jalson::json_array msg;
          msg.push_back( INVOCATION );
          msg.push_back( request_id );
          msg.push_back( rpc.registration_id );
          msg.push_back( jalson::json_object() );
          msg.push_back( jalson::json_array() );
          msg.push_back( jalson::json_object() );

          return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
                                                                    nullptr );
        };

      m_sesman->send_request(rpc.sesionh, INVOCATION, internal_req_id, msg_builder2);
    }
  }
  else
  {
    _WARN_("Failed to find RPC for CALL request: " << rpc.uri);
    // TODO : test this path; should reulst in a ERROR going back to the
    // client process, and that it can successfully handle it.
    throw event_error(WAMP_ERROR_URI_NO_SUCH_PROCEDURE);
  }
}



} // namespace
