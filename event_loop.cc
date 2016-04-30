#include "event_loop.h"
#include "rpc_man.h"
#include "pubsub_man.h"
#include "SessionMan.h"
#include "WampTypes.h"
#include "Logger.h"
#include "utils.h"


namespace XXX {

// TODO: set to 1000; for testing, set to 1 ms
#define SYSTEM_HEARTBEAT_MS 100000

/* Constructor */
event_loop::event_loop(Logger *logptr)
  : __logptr(logptr),
    m_continue(true),
    m_thread(&event_loop::eventmain, this),
    m_rpcman(nullptr),
    m_pubsubman(nullptr),
    m_sesman(nullptr),
    m_handlers( WAMP_MSGID_MAX ), /* initial handles are empty */
    m_last_hb( std::chrono::steady_clock::now() )
{
}

/* Destructor */
event_loop::~event_loop()
{
  stop();
}

void event_loop::stop()
{
  m_continue = false;
  push( 0 );
  if (m_thread.joinable()) m_thread.join();
}

void event_loop::set_rpc_man(rpc_man* r)
{
  m_rpcman = r;
}
void event_loop::set_pubsub_man(pubsub_man* p)
{
  m_pubsubman = p;
}

void event_loop::set_session_man(SessionMan* sm)
{
  m_sesman = sm;
}

void event_loop::set_handler(unsigned int eventid, event_cb handler)
{
  if (eventid > m_handlers.size() )
  {
    _ERROR_("resizing handler vector for eventid " << eventid);
    m_handlers.resize( eventid+1 );
  }
  m_handlers[ eventid ] = handler;

}

void event_loop::set_handler2(unsigned int eventid, event_cb2 handler)
{
  if (eventid > m_handlers2.size() )
  {
    m_handlers2.resize( eventid+1 );
  }
  m_handlers2[ eventid ] = handler;
}

/*
  shared_ptr<> sp
  push_
*/

// void push(std::shared_ptr<event>& ev)
// {
//   if (ev == 0) m_continue = false;

//   std::unique_lock<std::mutex> guard(m_mutex);
//   m_queue.push_back( e );
//   m_condvar.notify_one();
// }

// TODO: general threading concner here.  How do I enqure that any users of this
// EVL dont make a call into here once self has started into the destructor????
void event_loop::push(event* ev)
{
  auto sp = std::shared_ptr<event>(ev);

  std::unique_lock<std::mutex> guard(m_mutex);
  m_queue.push_back( std::move(sp) );
  m_condvar.notify_one();
}

void event_loop::push(std::shared_ptr<event> sp)
{
  std::unique_lock<std::mutex> guard(m_mutex);
  m_queue.push_back( sp );
  m_condvar.notify_one();
}


void event_loop::hb_check()
{
  auto tnow = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(tnow - m_last_hb);
  if (elapsed.count() >= SYSTEM_HEARTBEAT_MS)
  {
    m_last_hb = tnow;
    if (m_sesman) m_sesman->handle_housekeeping_event();
  }
}

void event_loop::eventloop()
{
  const auto timeout = std::chrono::milliseconds( SYSTEM_HEARTBEAT_MS );

  /* A note on memory management of the event objects.  Once they are pushed,
   * they are stored as shared pointers.  This allows other parts of the code to
   * take ownership of the resource, if they so wish.
   */
  while (m_continue)
  {
    std::vector< std::shared_ptr<event> > to_process;
    {
      std::unique_lock<std::mutex> guard(m_mutex);
      m_condvar.wait_for(guard,
                         timeout,
                         [this](){ return !m_queue.empty() && m_queue.size()>0; } );
      to_process.swap( m_queue );
    }

    if (!m_continue) return;

    for (auto & ev : to_process)
    {
      if (!m_continue) return;
      if (ev == 0) continue; // TODO: use a proper sentinel event

      hb_check(); // check for when there are many items work through

      bool error_caught = true;
      event_error wamperror("unknown");

      try
      {
        process_event( ev.get() );
        error_caught = false;
      }
      catch ( const event_error & er)
      {
        _ERROR_( "caught event_error error, uri: "<< er.error_uri<< ", what:" << er.what());
        /* only basic code in here, to remove risk of a throw while an exception
         * is already active. */
        wamperror = er;
      }
      catch ( const std::exception& ex)
      {
        _WARN_( "caught exception during process_event: " << ex.what() );
        /* only basic code in here, to remove risk of a throw while an exception
         * is already active. */
      }
      catch ( ... )
      {
        // TODO: cannot do much in here, because might throw
        _ERROR_( "caught unknown error" );
      }

      if (error_caught)
      {
        try
        {
          // TODO: do I want all errors to result in a reply message being sent?
          process_event_error( ev.get(), wamperror );
        }
        catch (std::exception& e)
        {
          _ERROR_( "failure while handing event error: " << e.what() );
        }
        catch ( ... )
        {

          // TODO: cannot do much in here, because might throw
        }
      }

    } // loop end


    to_process.clear();

    // for when we simply timed out and never went into the loop
    hb_check();
  }
}

void event_loop::eventmain()
{
  while (m_continue)
  {
    try
    {
      eventloop();
    }
    catch (const std::exception& e)
    {
      _ERROR_("exception in eventmain: " << e.what());
    }
    catch (...)
    {
      _ERROR_("unknown exception in eventmain");
    }
  }
}

//----------------------------------------------------------------------

void event_loop::process_event(event * ev)
{

  switch ( ev->type )
  {
    case event::outbound_publish:
    {
      ev_outbound_publish* ev2 = dynamic_cast<ev_outbound_publish*>(ev);
      process_outbound_publish(ev2);
      break;
    }
    case event::inbound_subscribed:
    {
      // TODO: create a template for this, which will throw etc.
      if (m_client_handler.handle_inbound_subscribed)
      {
        ev_inbound_subscribed* ev2 = dynamic_cast<ev_inbound_subscribed*>(ev);
        if (ev2) m_client_handler.handle_inbound_subscribed( ev2 );
      }
      break;
    }
    case event::outbound_subscribe :
    {
      // TODO: create a template for this, which will throw etc.
      ev_outbound_subscribe* ev2 = dynamic_cast<ev_outbound_subscribe*>(ev);
      process_outbound_subscribe(ev2);
      break;
    }
    case event::outbound_call_event :
    {
      // TODO: create a template for this, which will throw etc.
      outbound_call_event* ev2 = dynamic_cast<outbound_call_event*>(ev);
      process_outbound_call(ev2);
      break;
    }
    case event::outbound_response_event :
    {
      // TODO: create a template for this, which will throw etc. Will be a
      // series error if the cast failes.
      outbound_response_event * ev2 = dynamic_cast<outbound_response_event *>(ev);
      process_outbound_response( ev2 );
      break;
    }
    case event::outbound_message :
    {
      // TODO: create a template for this, which will throw etc. Will be a
      // series error if the cast failes.
      outbound_message * ev2 = dynamic_cast<outbound_message *>(ev);
      process_outbound_message( ev2 );
      break;
    }
    case event::session_state_event :
    {
      ev_session_state_event * ev2 = dynamic_cast<ev_session_state_event *>(ev);
      if (m_sesman) m_sesman->handle_event( ev2 );
      if (m_pubsubman) m_pubsubman->handle_event( ev2 );
      break;
    }
    case event::router_session_connect_fail :
    {
      if (m_client_handler.handle_router_session_connect_fail)
      {
        m_client_handler.handle_router_session_connect_fail(
          dynamic_cast<ev_router_session_connect_fail*>(ev)
          );
      }
      break;
    }
    case event::internal_publish :
    {
      if (m_pubsubman)
        m_pubsubman->handle_event(dynamic_cast<ev_internal_publish *>(ev));
      break;
    }
    case event::inbound_message :
    {
      ev_inbound_message * ev2 =
        dynamic_cast<ev_inbound_message*>(ev);
      if (ev2==nullptr) throw std::runtime_error("invalid inbound_message event");

      switch ( ev2->msg_type )
      {
        case YIELD : { process_inbound_yield( ev2 ); break; }
        case SUBSCRIBE:
        {
          // TODO: improve this
          event_cb& cb = m_handlers[ ev2->msg_type ];
          if (cb) cb( ev );
          break;
        }
        case ERROR : {  process_inbound_error( ev ); break; }
        case REGISTER :
        {
          if (!m_rpcman) throw event_error(WAMP_ERROR_URI_NO_SUCH_PROCEDURE);

          // Register the RPC. Once this function has been called, we should
          // expect that requests can be sent immediately, so its important that
          // we immediately sent the registration ID to the peer, before requests
          // arrive.
          int registration_id = m_rpcman->handle_inbound_REGISTER(ev2);

          jalson::json_array msg;
          msg.push_back( REGISTERED );
          msg.push_back( ev2->ja[1] );
          msg.push_back( registration_id );
          m_sesman->send_to_session( ev2->src, msg );

          break;
        }
        case EVENT :
          if (m_client_handler.handle_inbound_event)
            m_client_handler.handle_inbound_event(ev2);
          break;
        case HEARTBEAT: break;
        case HELLO :
        case RESULT :
        case REGISTERED :
        case INVOCATION :
        case CHALLENGE :
        case AUTHENTICATE :
        case CALL :
        {
          event_cb2& cb = m_handlers2[ ev2->msg_type ];
          if (cb) cb( ev2 );
          else
          {
            _ERROR_( "no handler for message type " << ev2->msg_type);
          }
          break;
        }
        case PUBLISH :
        {
          if (m_pubsubman)
            m_pubsubman->handle_inbound_publish(ev2);
          else
            _WARN_("unable to handle inbound PUBLISH message");
          break;
        }
        default:
        {
          // TODO: probably should reply here
          std::ostringstream os;
          os << "msg type " << ev2->msg_type << " not supported"; // DJS
          _ERROR_( os.str() );
          throw std::runtime_error(os.str());
        }
      }
      break;
    }
    default:
    {
      _ERROR_( "unsupported event type " << ev->type );
    }
  }

}

void event_loop::process_event_InboundCall(event* )
{
}


void event_loop::process_event_error(event* ev, event_error& er)
{

  if (er.msg_type != UNDEF)
  {
    /* new style error */
    jalson::json_array msg;
    msg.push_back( ERROR );
    msg.push_back( er.msg_type );
    msg.push_back( er.request_id );
    msg.push_back( jalson::json_object() );
    msg.push_back( er.error_uri );
    msg.push_back( jalson::json_array() );
    msg.push_back( jalson::json_object() );
    m_sesman->send_to_session( ev->src, msg );
    return;
  }

/*
    [
      ERROR,
      CALL,
      CALL.Request|id,
      Details|dict,
      Error|uri,
      Arguments|list,
      ArgumentsKw|dict
    ]
*/

  ev_inbound_message * ev2 = dynamic_cast<ev_inbound_message*>(ev);
  if (ev2)
  {
    switch ( ev2->msg_type )
    {
      case CALL :
      {
        jalson::json_array msg;
        msg.push_back( ERROR );
        msg.push_back( CALL );
        msg.push_back( jalson::get_copy(ev2->ja,1,jalson::json_value::make_int(0)));
        msg.push_back( jalson::json_object() );
        msg.push_back( er.error_uri );
        msg.push_back( jalson::json_array() );
        msg.push_back( jalson::json_object() );

        m_sesman->send_to_session( ev->src, msg );
        break;
      }
      case REGISTER :
      {
        jalson::json_array msg;
        msg.push_back( ERROR );
        msg.push_back( REGISTER );
        msg.push_back( jalson::get_copy(ev2->ja,1,jalson::json_value::make_int(0)));
        msg.push_back( jalson::json_object() );
        msg.push_back( er.error_uri );
        msg.push_back( jalson::json_array() );
        msg.push_back( jalson::json_object() );
        msg.push_back( "qazwsx" );

        m_sesman->send_to_session( ev2->src, msg );
        break;
      }
      default:
      {
        THROW(std::runtime_error,
              "unsupported event type " << ev2->msg_type );
      }
    }
  }

}


struct Request_INVOCATION_CB_Data : public Request_CB_Data
{
  Request_INVOCATION_CB_Data()
    : cb_data( nullptr )
  {
  }
  std::string procedure;
  void * cb_data;  // TODO: just change to a outbound_request_type
};

//----------------------------------------------------------------------

  void event_loop::process_inbound_error(event* /*e*/)
{

  // Request_INVOCATION_CB_Data* request_cb_data
  //   = dynamic_cast<Request_INVOCATION_CB_Data*>( e->cb_data );

  // if (request_cb_data != nullptr)
  // {
  //   outbound_call_event* origev = ( outbound_call_event*)request_cb_data->cb_data;
  //   if (origev && origev->cb)
  //   {

  //     // TODO: create a generic callback function, which does all the exception
  //     // catch/log etc
  //     try
  //     {

  //       call_info info; // TODO: dfill in
  //       // TODO: should use an error callback
  //       wamp_args args;
  //       origev->cb(info, args, origev->cb_user_data);  /* TODO: take from network message */
  //     }
  //     catch(...)
  //     {
  //       // TODO: log exceptions here
  //     }
  //   }
  // }
  // else
  // {
  //   _ERROR_( "error, no request_cb_data found\n" );
  // }
  _ERROR_("TODO: put in support for handling inbound errors, and directing to call handler");
}
//----------------------------------------------------------------------
void event_loop::process_inbound_yield(ev_inbound_message* e)
{
  /* This handles a YIELD message received off a socket.  There are two possible
    options next.  Either route to the session which originated the CALL.  Or,
    if we can find a local callback function, invoke that.
   */


  // new .... see if we have an external handler
  event_cb& cb = m_handlers[ e->msg_type ];
  if (cb)
  {
    cb( e );
    return;
  }



  /*  NOTICE!!!

      This was the original approach for having a YIELD and translating to
      callback into user code. I.e., the callback was invoked from the event
      loop.  In the new approach, the callback is invoked from the
      client_service.

   */

  // Request_INVOCATION_CB_Data* request_cb_data
  //   = dynamic_cast<Request_INVOCATION_CB_Data*>( e->cb_data );

  // if (request_cb_data != nullptr)
  // {
  //   outbound_call_event* origev = ( outbound_call_event*)request_cb_data->cb_data;
  //   if (origev && origev->cb)
  //   {

  //     // TODO: create a generic callback function, which does all the exception
  //     // catch/log etc
  //     try
  //     {
  //       call_info info; // TODO: dfill in
  //       info.reqid = e->ja[1].as_uint();
  //       info.procedure = origev->rpc_name;

  //       wamp_args args;
  //       args.args    = e->ja[3]; // dont care about the type
  //       args.options = e->ja[2].as_object();  // TODO: need to pre-verify the message

  //       origev->cb(info, args, origev->cb_user_data); /* TODO: take from network message */
  //     }
  //     catch(...)
  //     {
  //       // TODO: log exceptions here
  //     }
  //   }
  //   else
  //   {
  //     _ERROR_( "cannot find any orig event for a received YIELD\n" );
  //   }
  // }
  // else
  // {
  //   _ERROR_( "error, no request_cb_data found" );
  // }
}

//----------------------------------------------------------------------

void event_loop::process_outbound_response(outbound_response_event* ev)
{
  /* Handle outbound response events.  Example flows coming through here are

     - YIELD
     - REGISTERED
     - ERROR

    Outbound means these these event are destined to end up sessions, and
    trigger an output IO event.

    TODO: add support here for REGISTERED, and see if we can remove the legacy
    implementation of REGISTERED.
   */

  build_message_cb_v4 msgbuilder;

  if (ev->response_type == YIELD)
  {
    msgbuilder = [ev](){
      jalson::json_array msg;
      msg.push_back(YIELD);
      msg.push_back(ev->reqid);
      msg.push_back(ev->options);
      if (ev->args.args_list.is_null() == false)
      {
        msg.push_back(ev->args.args_list);
      }
      return msg;
    };
  }
  if (ev->response_type == SUBSCRIBED)
  {
    msgbuilder = [ev](){
      jalson::json_array msg;
      msg.push_back(SUBSCRIBED);
      msg.push_back(ev->reqid);
      msg.push_back(ev->subscription_id);
      if (ev->args.args_list.is_null() == false)
      {
        msg.push_back(ev->args.args_list);
      }
      return msg;
    };
  }
  else if (ev->response_type == ERROR)
  {
    msgbuilder = [ev](){
      jalson::json_array msg;
      msg.push_back(ERROR);
      msg.push_back(ev->request_type);
      msg.push_back(ev->reqid);
      msg.push_back(ev->options);
      msg.push_back(ev->error_uri);
      return msg;
    };
  }
  else if (ev->response_type == RESULT)
  {
    msgbuilder = [ev](){
      jalson::json_array msg;
      msg.push_back(RESULT);
      msg.push_back(ev->reqid);
      msg.push_back(ev->options);
      if (ev->args.args_list.is_null() == false)
      {
        msg.push_back(ev->args.args_list);
      }
      return msg;
    };
  }
  else
  {
    throw std::runtime_error("unknown response_type");
  }

  m_sesman->send_to_session(ev->destination, msgbuilder);

}

//----------------------------------------------------------------------

void event_loop::process_outbound_message(outbound_message* ev)
{
  m_sesman->send_to_session(ev->destination, ev->ja);
}

//----------------------------------------------------------------------

void event_loop::process_outbound_call(outbound_call_event* ev)
{
  // not good... we need a to a copy of the event for the later arrival of the
  // YIELD/ERROR respons.  Eventually I need to try to just steal the source
  // event.
  //outbound_call_event * copy = new outbound_call_event( *ev );

  // also not good ... need to create the request content data.  Is there way to
  // just use the source event object directly?
  //Request_INVOCATION_CB_Data* cb_data = new Request_INVOCATION_CB_Data(); // TODO: memleak?
  //cb_data->cb_data = copy;

  build_message_cb_v2 msg_builder2 = [&](int request_id)
    {

      jalson::json_array msg;
      msg.push_back( CALL );
      msg.push_back( request_id );
      msg.push_back( ev->options );
      msg.push_back( ev->rpc_name );
      if (ev->args.args_list.is_null() == false)
      {
        msg.push_back( ev->args.args_list );
      }

      return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
                                                                nullptr );

    };

  m_sesman->send_request( ev->dest, CALL, ev->internal_req_id, msg_builder2);
}

//----------------------------------------------------------------------

void event_loop::process_outbound_subscribe(ev_outbound_subscribe* ev)
{
  build_message_cb_v2 msg_builder2 = [&](int request_id)
    {
      jalson::json_array msg;
      msg.push_back( SUBSCRIBE );
      msg.push_back( request_id );
      msg.push_back( jalson::json_object() );
      msg.push_back( ev->uri );

      return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
                                                                nullptr );

    };

  m_sesman->send_request( ev->dest,SUBSCRIBE , ev->internal_req_id, msg_builder2);
}

//----------------------------------------------------------------------

void event_loop::process_outbound_publish(ev_outbound_publish* ev)
{
  jalson::json_array msg;
  msg.push_back( PUBLISH );
  msg.push_back( 0 ); // set in the callback, below

  if (ev->use_patch)
  {
    msg.push_back( jalson::json_object() );
    msg.push_back( ev->uri );
    msg.push_back( ev->patch );
  }
  else
  {
    msg.push_back( ev->opts );
    msg.push_back( ev->uri );
    msg.push_back( ev->args_list );
    msg.push_back( ev->args_dict );
  }

  build_message_cb_v2 msg_builder2 = [&msg](int request_id)
    {
      msg[1] = request_id;

      // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
      return std::pair< jalson::json_array, Request_CB_Data*> ( msg, nullptr );

    };

  // TODO: instead of 0, need to have a valie intenral request id
  for (auto & sh : ev->targets)
    m_sesman->send_request(sh, PUBLISH, 0, msg_builder2);
}


} // namespace XXX
