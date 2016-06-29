#include "kernel.h"

#include "logger.h"
#include "IOLoop.h"
#include "event_loop.h"

#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/time.h>
#include <stdio.h>

namespace XXX {

/* Constructor */
kernel::kernel(logger* logptr)
  : __logptr(logptr),
    m_io_loop( new IOLoop(*this) ),
    m_evl( new event_loop(logptr) )
{
}

/* Destructor */
kernel::~kernel()
{
  // TODO: dont think this is the best way to shutdown.  Should start by trying
  // to close all the sessions.
  m_io_loop->stop();
  m_evl->stop();

  m_evl.reset();
}

void kernel::start()
{
  /* USER thread */

  m_io_loop->start(); // returns immediately
}

logger * kernel::get_logger()
{
  return __logptr;
}

IOLoop*  kernel::get_io()
{
  return m_io_loop.get();
}

event_loop* kernel::get_event_loop()
{
  return m_evl.get();
}




stdout_logger::stdout_logger(std::ostream& __os,
                             int __level,
                             bool __incsource)
  : m_stream(__os),
    m_level(__level),
    m_incsource(__incsource)

{
}


nlogger stdout_logger::create(std::ostream& stream,
                              nlogger::Level level,
                              bool inc_file_and_line)
{
  std::shared_ptr<stdout_logger> sp(
    new stdout_logger(stream, level, inc_file_and_line) );

  nlogger the_logger;

  the_logger.wants = [sp](nlogger::Level l)
    {
      return l <= sp->m_level;
    };

  the_logger.write = [sp](nlogger::Level l, const char* msg, const char* file, int ln)
  {
    if (l <= sp->m_level) sp->dolog("XXX", msg, file, ln);
  };

  return the_logger;
}


void stdout_logger::stdout_logger::dolog(const char* level,
                                         const char* s,
                                         const char* file,
                                         int ln)
{
  int tid = syscall(SYS_gettid);

  // get current time
  timeval now;
  struct timezone * const tz = NULL; /* not used on Linux */
  gettimeofday(&now, tz);

  // break time down into parts
  struct tm parts;
  localtime_r(&now.tv_sec, &parts);

  // build timestamp
  char timestamp[30];
  snprintf(timestamp,
           sizeof(timestamp),
           "%02d%02d%02d-%02d:%02d:%02d.%06lu ",
           parts.tm_year + 1900,
           parts.tm_mon + 1,
           parts.tm_mday,
           parts.tm_hour,parts.tm_min,parts.tm_sec,now.tv_usec);


  std::lock_guard<std::mutex> lock( m_mutex );
  m_stream << timestamp;
  m_stream << tid << " ";
  m_stream << level << " : ";
  m_stream << s;

  if (m_incsource && file)
  {
    m_stream << " (" << file << ":" << ln << ") ";
  }
  m_stream << std::endl;
}


} // namespace XXX
