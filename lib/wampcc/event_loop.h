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

namespace wampcc
{

class kernel;
struct event;
struct logger;

/** Event thread */
class event_loop
{
public:
  /* Signature for timer callbacks that can be registered with the event loop.
   * The return value indicates the delay to use for subsequent invocation of
   * the timer function, or 0 if the function should not be invoked again. */
  typedef std::function<std::chrono::milliseconds()> timer_fn;

  event_loop(kernel*);
  event_loop(const event_loop&) = delete;
  event_loop& operator=(const event_loop&) = delete;
  ~event_loop();

  /** Perform synchronous stop of the event loop.  On return, the EV thread will
   * have been joined. */
  void sync_stop();

  /** Post a function object that is later invoked on the event thread. */
  void dispatch(std::function<void()> fn);

  /** Post a timer function which is invoked after the elapsed time. */
  void dispatch(std::chrono::milliseconds, timer_fn fn);

  /** Determine whether the current thread is the EV thread. */
  bool this_thread_is_ev() const;

private:

  void handle_exception(const char* stage);
  void eventloop();
  void eventmain();

  void dispatch(std::chrono::milliseconds, std::shared_ptr<event>);

  kernel* m_kernel;
  logger& __logger; /* name chosen for log macros */

  bool m_continue;

  std::list<std::shared_ptr<event>> m_queue;
  std::mutex m_mutex;
  std::condition_variable m_condvar;
  std::multimap<std::chrono::steady_clock::time_point, std::shared_ptr<event>>
      m_schedule;

  synchronized_optional<std::thread::id> m_thread_id;

  std::thread m_thread; // prefer as final member, avoid race conditions
};

} // namespace wampcc

#endif
