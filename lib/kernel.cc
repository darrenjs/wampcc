/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/kernel.h"

#include "wampcc/io_loop.h"
#include "wampcc/event_loop.h"
#include "wampcc/ssl.h"
#include "config.h"

#include <iostream>

#include <unistd.h>
#include <sys/syscall.h> /* For SYS_xxx definitions */
#include <sys/time.h>
#include <stdio.h>


namespace wampcc
{

const char* name() { return PACKAGE_NAME; }
const char* name_version() { return PACKAGE_STRING; }
int major_version() { return WAMPCC_MAJOR_VERSION; }
int minor_version() { return WAMPCC_MINOR_VERSION; }
int micro_version() { return WAMPCC_MICRO_VERSION; }


config::config()
  : socket_buffer_max_size_bytes(65536), socket_max_pending_write_bytes(65536),
    ssl(false)
{

}



/* Constructor */
kernel::kernel(config conf, logger nlog)
  : m_config(conf),
    __logger(nlog)
{
  // SSL initialisation can fail, so we start the loops only after it has been
  // set up
  if (conf.ssl.enable)
    m_ssl.reset(new ssl_context(conf.ssl));

  m_io_loop.reset(new io_loop(*this));
  m_evl.reset(new event_loop(this));
}

/* Destructor */
kernel::~kernel()
{
  /* stop IO loop first, which will include closing all outstanding socket
   * resources, and as that happens, events are pushed onto the event queue
   * which is still operational */
  m_io_loop->sync_stop();
  m_evl->sync_stop();
}

io_loop* kernel::get_io() { return m_io_loop.get(); }

event_loop* kernel::get_event_loop() { return m_evl.get(); }

ssl_context* kernel::get_ssl() { return m_ssl.get(); }

int logger::levels_upto(Level l)
{
  int r(0);
  for (int i = 1; i <= l; i <<= 1)
    r |= i;
  return r;
}


class stdout_logger
{
public:
  stdout_logger(std::ostream& __os, bool __incsource)
    : m_stream(__os), m_incsource(__incsource)
  {
  }

  void write(logger::Level, const std::string&, const char*, int);

private:
  stdout_logger(const stdout_logger&) = delete;
  stdout_logger& operator=(const stdout_logger&) = delete;

  std::ostream& m_stream;
  bool m_incsource;
  std::mutex m_mutex;
};


logger logger::stdlog(std::ostream& ostr, int level_mask, bool inc_src)
{
  auto sp = std::make_shared<stdout_logger>(ostr, inc_src);

  logger my_logger;

  my_logger.wants_level =
      [level_mask](logger::Level l) { return l bitand level_mask; };

  my_logger.write = [level_mask, sp](logger::Level l, const std::string& msg,
                                     const char* file, int ln) {
    if (l bitand level_mask)
      sp->write(l, msg, file, ln);
  };

  return my_logger;
}

logger logger::stdout() { return stdlog(std::cout, levels_upto(eInfo), true); }


static const char* level_str(logger::Level l)
{
  switch (l) {
    case logger::eError:
      return "ERROR";
    case logger::eWarn:
      return " WARN";
    case logger::eInfo:
      return " INFO";
    case logger::eDebug:
      return "DEBUG";
  }

  return "unhandled_switch";
}


void stdout_logger::stdout_logger::write(logger::Level l, const std::string& s,
                                         const char* file, int ln)
{
  int tid = syscall(SYS_gettid);

  // get current time
  timeval now;
  struct timezone* const tz = NULL; /* not used on Linux */
  gettimeofday(&now, tz);

  // break time down into parts
  struct tm parts;
  localtime_r(&now.tv_sec, &parts);

  // build timestamp
  char timestamp[30];
  snprintf(timestamp, sizeof(timestamp), "%02d%02d%02d-%02d:%02d:%02d.%06lu ",
           parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday, parts.tm_hour,
           parts.tm_min, parts.tm_sec, now.tv_usec);


  std::lock_guard<std::mutex> lock(m_mutex);
  m_stream << timestamp;
  m_stream << tid << " ";
  m_stream << level_str(l) << " ";
  m_stream << s;

  if (m_incsource && file) {
    m_stream << " (" << file << ":" << ln << ") ";
  }
  m_stream << std::endl;
}


logger logger::nolog()
{
  logger my_logger;

  my_logger.wants_level = [](logger::Level) { return false; };

  my_logger.write = [](logger::Level, const std::string&, const char*, int) {};

  return my_logger;
}

} // namespace wampcc
