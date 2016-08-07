#ifndef XXX_EVENT_LOOP_H
#define XXX_EVENT_LOOP_H

#include "wamp_types.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <list>
#include <map>

namespace XXX {

struct logger;
struct event;

//using hb_func = std::function< bool(void) >;

class event_loop
{
public:
  event_loop(logger&);
  ~event_loop();

  void stop();

  void init();

  void dispatch(std::function<void()> fn);
  void dispatch(std::chrono::milliseconds, std::function<void()> fn);

  // void add_hb_target(hb_func);

private:
  event_loop(const event_loop&); // no copy
  event_loop& operator=(const event_loop&); // no assignment


  void eventloop();
  void eventmain();

  void process_event(event* e);

  // void hb_check();


  logger & __logger; /* name chosen for log macros */

  bool m_continue;

  std::shared_ptr<event> m_kill_event;
  std::list< std::shared_ptr<event> > m_queue;
  std::mutex m_mutex;
  std::condition_variable m_condvar;
  std::thread m_thread;
  std::multimap< std::chrono::steady_clock::time_point, std::shared_ptr<event>  > m_schedule;

//  std::chrono::time_point<std::chrono::steady_clock> m_last_hb;

  // std::list< hb_func > m_hb_targets;
  // std::mutex           m_hb_targets_mutex;
};

} // namespace XXX

#endif
