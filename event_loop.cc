#include "event_loop.h"
#include "rpc_man.h"
#include "pubsub_man.h"
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
#define SYSTEM_HEARTBEAT_MS 1000

/* Constructor */
event_loop::event_loop(Logger *logptr)
  : __logptr(logptr),
    m_continue(true),
    m_kill_event( std::make_shared< event > (event::e_kill) ),
    m_thread(&event_loop::eventmain, this),
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

  {
    std::unique_lock<std::mutex> guard(m_mutex);
    m_queue.push_back(m_kill_event);
    m_condvar.notify_one();
  }

  if (m_thread.joinable()) m_thread.join();
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


void event_loop::dispatch(std::function<void()> fn)
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

    std::list< hb_func > hb_tmp;
    {
      std::unique_lock<std::mutex> guard(m_hb_targets_mutex);
      hb_tmp.swap( m_hb_targets );
    }

    for (auto hb_fn : hb_tmp)
    {
      try
      {
        bool continue_hb = hb_fn();
        if (continue_hb) add_hb_target( std::move(hb_fn) );
      }
      catch (...)  { log_exception(__logptr, "heartbeat callback"); }
    }
  }
}


void event_loop::eventloop()
{
  /* A note on memory management of the event objects.  Once they are pushed,
   * they are stored as shared pointers.  This allows other parts of the code to
   * take ownership of the resource, if they so wish.
   */
  std::vector< std::shared_ptr<event> > to_process;
  while (m_continue)
  {
    to_process.clear();

    // calculate the sleep interval
    auto tnow = std::chrono::steady_clock::now();
    int interval_since_hb_ms = std::chrono::duration_cast<std::chrono::milliseconds>(tnow - m_last_hb).count();
    if (interval_since_hb_ms < 0) interval_since_hb_ms = SYSTEM_HEARTBEAT_MS;

    // use max so that if we missed a HB, then we set timeout to 0
    std::chrono::milliseconds sleep_interval (
      std::max(0, SYSTEM_HEARTBEAT_MS - interval_since_hb_ms));

    if (sleep_interval.count() == 0)
    {
      sleep_interval = std::chrono::milliseconds(SYSTEM_HEARTBEAT_MS);
      hb_check();
    }

    {
      std::unique_lock<std::mutex> guard(m_mutex);
      m_condvar.wait_for(guard,
                         sleep_interval,
                         [this](){ return !m_queue.empty() && m_queue.size()>0; } );
      to_process.swap( m_queue );
    }

    if (!m_continue) return;

    for (auto & ev : to_process)
    {
      if (!m_continue) return;
      if (ev == m_kill_event) continue;

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

    if (auto sp = ev->src.lock())
    {
      jalson::json_array msg;
      msg.push_back( ERROR );
      msg.push_back( er.msg_type );
      msg.push_back( er.request_id );
      msg.push_back( jalson::json_object() );
      msg.push_back( er.error_uri );
      msg.push_back( jalson::json_array() );
      msg.push_back( jalson::json_object() );

      sp->send_msg( msg );
    }
    return;
  }

}


void event_loop::add_hb_target(hb_func f)
{
  std::unique_lock<std::mutex> guard(m_hb_targets_mutex);
  m_hb_targets.push_back(std::move(f));
}

} // namespace XXX
