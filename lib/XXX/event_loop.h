#ifndef XXX_EVENT_LOOP_H
#define XXX_EVENT_LOOP_H

#include "XXX/types.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <list>
#include <map>

namespace XXX {

struct logger;
class kernel;
struct event;

//using hb_func = std::function< bool(void) >;

class event_loop
{
public:
  event_loop(kernel*);
  ~event_loop();

  void stop();

  void dispatch(std::function<void()> fn);
  void dispatch(std::chrono::milliseconds, std::function<int()> fn);

  /** Test whether the current thread is the EV thread */
  bool this_thread_is_ev() const;

  // void add_hb_target(hb_func);

private:
  event_loop(const event_loop&); // no copy
  event_loop& operator=(const event_loop&); // no assignment


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

} // namespace XXX

#endif
