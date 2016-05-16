#ifndef XXX_KERNEL_H
#define XXX_KERNEL_H

#include <memory>

namespace XXX {

class IOLoop;
class Logger;
class event_loop;

class kernel
{
public:
  kernel(Logger*);
  ~kernel();

  void start();

  kernel(const kernel&) = delete;
  kernel& operator=(const kernel&) = delete;

  Logger *     get_logger();
  IOLoop*      get_io();
  event_loop*  get_event_loop();

private:

  Logger *__logptr; /* name chosen for log macros */
  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
};

} // namespace XXX

#endif
