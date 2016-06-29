#ifndef XXX_KERNEL_H
#define XXX_KERNEL_H

#include <memory>
#include <mutex>


namespace XXX {

class IOLoop;
class logger;
class event_loop;


struct nlogger
{
  enum Level {eError = 0x1,
              eWarn  = 0x2,
              eInfo  = 0x4,
              eDebug = 0x8};

  static int all_levels() { return eError | eWarn | eInfo | eDebug; }

  std::function<bool(Level)> wants;
  std::function<void(Level, const char*, const char* file, int ln)> write;
};


class kernel
{
public:
  kernel(logger*);
  ~kernel();

  void start();

  kernel(const kernel&) = delete;
  kernel& operator=(const kernel&) = delete;

  logger *     get_logger();
  IOLoop*      get_io();
  event_loop*  get_event_loop();

private:

  logger *__logptr; /* name chosen for log macros */
  std::unique_ptr<IOLoop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
};



class stdout_logger
{
public:

  stdout_logger(std::ostream&,
                int levels_to_log,
                bool inc_file_and_line=false);

  stdout_logger(const stdout_logger&) = delete;
  stdout_logger& operator=(const stdout_logger&) = delete;

  static nlogger create(std::ostream&,
                        nlogger::Level level,
                        bool inc_file_and_line=false);

private:
  void dolog(const char*, const char*, const char*, int);

  std::ostream&             m_stream;
  int                       m_level;
  bool                      m_incsource;
  std::mutex                m_mutex;
};



} // namespace XXX

#endif
