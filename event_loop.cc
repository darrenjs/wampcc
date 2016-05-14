#include "event_loop.h"
#include "rpc_man.h"
#include "pubsub_man.h"
#include "SessionMan.h"
#include "WampTypes.h"
#include "Logger.h"
#include "utils.h"


namespace XXX {

struct ev_function_dispatch : event
{
  ev_function_dispatch(std::function<void()> __fn) :
    event(event::function_dispatch),
    fn(__fn)
  {}

  std::function<void()> fn;
};

// TODO: set to 1000; for testing, set to 1 ms
#define SYSTEM_HEARTBEAT_MS 100000

/* Constructor */
event_loop::event_loop(Logger *logptr)
  : __logptr(logptr),
    m_continue(true),
    m_thread(&event_loop::eventmain, this),
    m_pubsubman(nullptr),
    m_sesman(nullptr),
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

void event_loop::set_pubsub_man(pubsub_man* p)
{
  m_pubsubman = p;
}

void event_loop::set_session_man(SessionMan* sm)
{
  m_sesman = sm;
}



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

void event_loop::push(std::function<void()> fn)
{
  push( new ev_function_dispatch(std::move(fn)) );
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
    case event::inbound_message :
    {
      ev_inbound_message * ev2 =
        dynamic_cast<ev_inbound_message*>(ev);
      if (ev2==nullptr) throw std::runtime_error("invalid inbound_message event");

      switch ( ev2->msg_type )
      {
        case REGISTER :
        {
          m_server_handler.handle_inbound_REGISTER(ev2);
          break;
        }
        case HEARTBEAT: break;
        case HELLO :
        case RESULT :
        case CHALLENGE :
        case AUTHENTICATE :
        case ERROR :
        {
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
    case event::function_dispatch :
    {
      ev_function_dispatch * ev2 =  dynamic_cast<ev_function_dispatch*>(ev);
      ev2->fn();
      break;
    }


    default:
    {
      _ERROR_( "unsupported event type " << ev->type );
    }
  }

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
