#include "XXX/event_loop.h"

#include "XXX/rpc_man.h"
#include "XXX/pubsub_man.h"
#include "XXX/log_macros.h"
#include "XXX/utils.h"

namespace XXX {

struct event
{
  enum Type
  {
    e_null = 0,
    e_kill,
    function_dispatch,
    timer_dispatch
  } type;

  event(Type t)
    : type(t)
  {}

  virtual ~event(){}
};


struct ev_function_dispatch : event
{
  ev_function_dispatch(std::function<void()> __fn) :
    event(event::function_dispatch),
    fn(__fn)
  {}

  std::function<void()> fn;
};

struct ev_timer_dispatch : event
{
  ev_timer_dispatch(std::function<int()> __fn) :
    event(event::timer_dispatch),
    fn(__fn)
  {}

  std::function<int ()> fn;
};


// #define SYSTEM_HEARTBEAT_MS 500

/* Constructor */
event_loop::event_loop(kernel* k)
  : m_kernel(k),
    __logger(k->get_logger()),
    m_continue(true),
    m_kill_event( std::make_shared< event > (event::e_kill) ),
    m_thread(&event_loop::eventmain, this)
//    m_last_hb( std::chrono::steady_clock::now() )
{
}


/* Destructor */
event_loop::~event_loop()
{
  stop();
}


void event_loop::stop()
{
  {
    std::unique_lock<std::mutex> guard(m_mutex);
    m_queue.push_back(m_kill_event);
    m_condvar.notify_one();
  }

  if (m_thread.joinable()) m_thread.join();
}


void event_loop::dispatch(std::function<void()> fn)
{
  auto event = std::make_shared<ev_function_dispatch>(std::move(fn));

  {
    std::unique_lock<std::mutex> guard(m_mutex);
    m_queue.push_back( std::move(event) );
    m_condvar.notify_one();
  }
}


void event_loop::dispatch(std::chrono::milliseconds delay, std::function<int()> fn)
{
  dispatch(delay, std::make_shared<ev_timer_dispatch>(std::move(fn)));
}

void event_loop::dispatch(std::chrono::milliseconds delay, std::shared_ptr<event> sp)
{
  auto tp_due = std::chrono::steady_clock::now() + delay;
  auto event  = std::make_pair(tp_due, std::move(sp));

  {
    std::unique_lock<std::mutex> guard(m_mutex);
    m_schedule.insert( std::move(event) );
    m_condvar.notify_one();
  }
}
// void event_loop::hb_check()
// {
//   auto tnow = std::chrono::steady_clock::now();
//   auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(tnow - m_last_hb);

//   if (elapsed.count() >= SYSTEM_HEARTBEAT_MS)
//   {
//     m_last_hb = tnow;

//     std::list< hb_func > hb_tmp;
//     {
//       std::unique_lock<std::mutex> guard(m_hb_targets_mutex);
//       hb_tmp.swap( m_hb_targets );
//     }

//     for (auto hb_fn : hb_tmp)
//     {
//       try
//       {
//         bool continue_hb = hb_fn();
//         if (continue_hb) add_hb_target( std::move(hb_fn) );
//       }
//       catch (...)  { log_exception(__logger, "heartbeat callback"); }
//     }
//   }
// }


void event_loop::eventloop()
{
  /* A note on memory management of the event objects.  Once they are pushed,
   * they are stored as shared pointers.  This allows other parts of the code to
   * take ownership of the resource, if they so wish.
   */
  std::list< std::shared_ptr<event> > to_process;
  while (m_continue)
  {
    to_process.clear();

    // // calculate the sleep interval
    // auto tnow = std::chrono::steady_clock::now();
    // int interval_since_hb_ms = std::chrono::duration_cast<std::chrono::milliseconds>(tnow - m_last_hb).count();
    // if (interval_since_hb_ms < 0) interval_since_hb_ms = SYSTEM_HEARTBEAT_MS;

    // // use max so that if we missed a HB, then we set timeout to 0
    // std::chrono::milliseconds sleep_interval (
    //   std::max(0, SYSTEM_HEARTBEAT_MS - interval_since_hb_ms));

    // if (sleep_interval.count() == 0)
    // {
    //   sleep_interval = std::chrono::milliseconds(SYSTEM_HEARTBEAT_MS);
    //   hb_check();
    // }

    {
      std::unique_lock<std::mutex> guard(m_mutex);

      while (m_continue && m_queue.empty() && m_queue.size()==0)
      {
        // identify range of scheduled events which are now due
        const auto tp_now = std::chrono::steady_clock::now();
        const auto upper_iter = m_schedule.upper_bound(tp_now);

        if (upper_iter == m_schedule.begin())
        {
          // no events due, so need to sleep
          if (m_schedule.empty())
          {
            m_condvar.wait(guard);
          }
          else
          {
            auto sleep_for = m_schedule.begin()->first - tp_now;
            m_condvar.wait_for(guard, sleep_for);
          }
        }
        else
        {
          for (auto iter = m_schedule.begin(); iter != upper_iter; ++iter)
            m_queue.push_back( std::move(iter->second) );
          m_schedule.erase(m_schedule.begin(), upper_iter);
        }
      }
      to_process.swap( m_queue );

      // m_condvar.wait_for(guard,
      //                    sleep_interval,
      //                    [this](){ return !m_queue.empty() && m_queue.size()>0; } );
      // to_process.swap( m_queue );

    }

    if (!m_continue) return; // needed?

    for (auto & ev : to_process)
    {
      if (!m_continue) return; // needed?
      if (ev == m_kill_event)
      {
        m_continue = false;
        continue;
      }

      //hb_check(); // check for when there are many items work through

      try
      {

        switch ( ev->type )
        {
          case event::function_dispatch :
          {
            ev_function_dispatch * ev2 = dynamic_cast<ev_function_dispatch*>(ev.get());
            ev2->fn();
            break;
          }
          case event::timer_dispatch :
          {
            ev_timer_dispatch * ev2 = dynamic_cast<ev_timer_dispatch*>(ev.get());
            int repeat_ms = ev2->fn();
            if (repeat_ms) dispatch(std::chrono::milliseconds(repeat_ms), ev);
            break;
          }
	        default: break;
        }


      }
      catch ( const std::exception& ex)
      {
        LOG_ERROR( "exception during process_event : " << ex.what() );
      }
      catch ( ... )
      {
        LOG_ERROR( "unknown exception during process_event" );
      }

    } // loop end
  }
}


void event_loop::eventmain()
{
  if (m_kernel->get_config().event_loop_start_fn)
    try {
      m_kernel->get_config().event_loop_start_fn();
    } catch(...){}

  while (m_continue)
  {
    try
    {
      eventloop();
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("ignoring exception in eventmain: " << e.what());
    }
    catch (...)
    {
      LOG_ERROR("ignoring unknown exception in eventmain");
    }
  }

  if (m_kernel->get_config().event_loop_end_fn)
    try {
      m_kernel->get_config().event_loop_end_fn();
    } catch(...){}

}



} // namespace XXX
