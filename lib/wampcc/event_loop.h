/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_EVENT_LOOP_H
#define WAMPCC_EVENT_LOOP_H

#include "wampcc/utils.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <list>
#include <map>

namespace wampcc {

struct logger;
class kernel;
struct event;

//using hb_func = std::function< bool(void) >;

class event_loop
{
public:

  /* Signature for timer callbacks that can be registered with the event loop.
   * The return value indicates the delay to use for subsequent invocation of
   * the timer function, or 0 if the function should not be invoked again. */
  typedef std::function<std::chrono::milliseconds()> timer_fn;

  event_loop(kernel*);
  ~event_loop();

  /** Perform synchronous stop of the event loop.  On return, the EV thread will
   * have been joined. */
  void sync_stop();

  void dispatch(std::function<void()> fn);
  void dispatch(std::chrono::milliseconds, timer_fn fn);

  /** Test whether the current thread is the EV thread */
  bool this_thread_is_ev() const;

  // void add_hb_target(hb_func);

private:
  event_loop(const event_loop&); // no copy
  event_loop& operator=(const event_loop&); // no assignment

  void handle_exception(const char* stage);
  void eventloop();
  void eventmain();

  void dispatch(std::chrono::milliseconds, std::shared_ptr<event>);

  // void hb_check();

  kernel * m_kernel;
  logger & __logger; /* name chosen for log macros */

  bool m_continue;

  std::shared_ptr<event> m_kill_event;
  std::list< std::shared_ptr<event> > m_queue;
  std::mutex m_mutex;
  std::condition_variable m_condvar;
  std::multimap< std::chrono::steady_clock::time_point, std::shared_ptr<event>  > m_schedule;

  // std::list< hb_func > m_hb_targets;
  // std::mutex           m_hb_targets_mutex;

  synchronized_optional<std::thread::id> m_ev_thread_id;

  std::thread m_thread; // must be final member to prevent race conditions
};

} // namespace wampcc

#endif
