/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/event_loop.h"

#include "wampcc/rpc_man.h"
#include "wampcc/pubsub_man.h"
#include "wampcc/log_macros.h"
#include "wampcc/utils.h"

#include <iostream>

namespace wampcc {

struct event
{
  enum event_type
  {
    null = 0,
    kill,
    function_dispatch,
    timer_dispatch
  } type;

  event(event_type t)
    : type(t)
  {}

  virtual ~event(){}
};


struct ev_function_dispatch : event
{
  ev_function_dispatch(std::function<void()> fn_) :
    event(event::function_dispatch),
    fn(std::move(fn_))
  {}

  std::function<void()> fn;
};

struct ev_timer_dispatch : event
{
  ev_timer_dispatch(event_loop::timer_fn fn_) :
    event(event::timer_dispatch),
    fn(std::move(fn_))
  {}

  event_loop::timer_fn fn;
};


event_loop::event_loop(kernel* k)
  : m_kernel(k),
    __logger(k->get_logger()),
    m_continue(true),
    m_kill_event( std::make_shared< event > (event::kill) ),
    m_thread(&event_loop::eventmain, this)
{
}


event_loop::~event_loop()
{
  sync_stop();
}


void event_loop::sync_stop()
{
  {
    std::lock_guard<std::mutex> guard(m_mutex);
    m_queue.push_back(m_kill_event);
    m_condvar.notify_one();
  }

  if (m_thread.joinable())
    m_thread.join();
}


void event_loop::dispatch(std::function<void()> fn)
{
  auto event = std::make_shared<ev_function_dispatch>(std::move(fn));

  {
    std::lock_guard<std::mutex> guard(m_mutex);
    m_queue.push_back( std::move(event) );
    m_condvar.notify_one();
  }
}


void event_loop::dispatch(std::chrono::milliseconds delay, timer_fn fn)
{
  dispatch(delay, std::make_shared<ev_timer_dispatch>(std::move(fn)));
}


void event_loop::dispatch(std::chrono::milliseconds delay, std::shared_ptr<event> sp)
{
  auto tp_due = std::chrono::steady_clock::now() + delay;
  auto event  = std::make_pair(tp_due, std::move(sp));

  {
    std::lock_guard<std::mutex> guard(m_mutex);
    m_schedule.insert( std::move(event) );
    m_condvar.notify_one();
  }
}


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

    for (auto & ev : to_process)
    {
      if (ev == m_kill_event)
      {
        m_continue = false;
        return;
      }

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
            auto repeat_ms = ev2->fn();
            if (repeat_ms.count() > 0)
              dispatch(repeat_ms, std::move(ev));
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


void event_loop::handle_exception(const char* stage)
{
  try {
    throw;
  }
  catch (const std::exception& e)
  {
    LOG_WARN("ignoring exception in eventmain, " << stage << ": " << e.what());
  }
  catch (...)
  {
    LOG_WARN("ignoring exception in eventmain. " << stage << ": unknown type");
  }
}


/* Entry point for the kernel's EV thread */
void event_loop::eventmain()
{
  scope_guard undo_thread_id([this](){
      m_ev_thread_id.release();
    });

  m_ev_thread_id.set_value(std::this_thread::get_id());


  if (m_kernel->get_config().event_loop_start_fn)
    try {
      m_kernel->get_config().event_loop_start_fn();
    }
    catch(...) {
      handle_exception("at start");
    }

  while (m_continue)
  {
    try {
      eventloop();
    }
    catch(...) {
      handle_exception("at main");
    }
  }

  if (m_kernel->get_config().event_loop_end_fn)
    try {
      m_kernel->get_config().event_loop_end_fn();
    }
    catch(...) {
      handle_exception("at end");
    }
}


bool event_loop::this_thread_is_ev() const
{
  return m_ev_thread_id.compare(std::this_thread::get_id());
}

} // namespace wampcc
