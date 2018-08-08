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
#include "wampcc/platform.h"

#include "config.h"

#include <iostream>

namespace wampcc
{

const char* package_name() { return WAMPCC_PACKAGE_NAME; }
const char* package_version() { return WAMPCC_PACKAGE_VERSION; }
const char* package_string() { return WAMPCC_PACKAGE_STRING; }
int major_version() { return WAMPCC_MAJOR_VERSION; }
int minor_version() { return WAMPCC_MINOR_VERSION; }
int micro_version() { return WAMPCC_MICRO_VERSION; }

static const char* level_str(logger::Level l);

std::mutex logger::lockable_console::stream_mutex ;
logger::lockable_console logger::lockable_cout;

static long default_socket_max_pending_write_bytes = 0x100000; // 1mb

config::config()
  : socket_max_pending_write_bytes(default_socket_max_pending_write_bytes),
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
    m_ssl.reset(new ssl_context(__logger, conf.ssl));

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

logger logger::stream(lockable_stream& ostr, int level_mask, bool inc_src)
{
  logger my_logger;

  my_logger.wants_level =
    [level_mask](logger::Level l) { return (l & level_mask) != 0; };

  my_logger.write = [&ostr, inc_src](logger::Level level,
                                     const std::string& msg,
                                     const char* file, int ln) {
    std::ostringstream oss;
    oss << wampcc::local_timestamp() << " "
        << wampcc::thread_id() << " "
        << level_str(level) << " "
    << msg;
    if (inc_src && file)
      oss << " (" << file << ":" << ln << ") ";

    ostr.lock();
     try {
       // std:endl should act directly on the stream object, so that stream can
       // detect it and trigger stream sync.
       ostr.stream() << oss.str() << std::endl;
     } catch (...) {}
    ostr.unlock();
  };

  return my_logger;
}


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
    case logger::eTrace:
      return "TRACE";
  }

  return "UNKNOWN";
}


logger logger::nolog()
{
  logger my_logger;

  my_logger.wants_level = [](logger::Level) { return false; };

  my_logger.write = [](logger::Level, const std::string&, const char*, int) {};

  return my_logger;
}


std::ostream& logger::lockable_console::stream()
{
  return std::cout;
}


} // namespace wampcc
