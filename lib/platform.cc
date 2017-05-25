/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <wampcc/platform.h>

#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <thread>

#ifndef _WIN32
#include <unistd.h>
#include <sys/syscall.h> /* For SYS_xxx definitions */
#include <sys/utsname.h>
#else
#include <Windows.h>
#endif

namespace wampcc
{

int thread_id()
{
#ifndef _WIN32
  return syscall(SYS_gettid);
#else
  return GetCurrentThreadId();
//return std::this_thread::get_id();
#endif
}

std::string local_timestamp()
{
#ifndef _WIN32
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

  return timestamp;
#else
  //  TODO: review this is correct, for Windows
  SYSTEMTIME st;
  GetLocalTime(&st);
  std::ostringstream oss;
  oss << std::setw(2) << st.wHour << ':' << std::setw(2) << st.wMinute << ':'
      << std::setw(2) << st.wSecond << '.' << std::setw(3) << st.wMilliseconds
      << '\n';
  return oss.str();
#endif
}


time_val time_now()
{
#ifndef _WIN32
  timeval epoch;
  gettimeofday(&epoch, nullptr);
  return {epoch.tv_sec, epoch.tv_usec};
#else
  return {0, 0}; /// TODO: add support for Windows
#endif
}

std::string hostname()
{
#ifndef _WIN32
  struct utsname buffer;
  if (uname(&buffer) != 0)
    throw std::runtime_error("uname failed");
  return buffer.nodename;
#else
  char temp[256];
  gethostname(temp, sizeof(temp));
  return temp;
#endif
}

} // wampcc
