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
  /* On Linux the thread-id returned via syscall is more useful than that C++
   * get_id(), since it will correspond to the values reported by top and other
   * tools. */
  return syscall(SYS_gettid);
#else
  return GetCurrentThreadId();
#endif
}


time_val time_now()
{
#ifndef _WIN32
  timeval epoch;
  gettimeofday(&epoch, nullptr);
  return {epoch.tv_sec, epoch.tv_usec};
#else
  SYSTEMTIME systime;
  GetSystemTime(&systime); // obtain milliseconds
  time_val::type_type now;
  time(&now); // seconds elapsed since midnight January 1, 1970
  time_val tv_systime{now, systime.wMilliseconds * 1000};

  /* C++11 chrono approach */
  /*
  auto ts = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
  time_val tv_chrono{ts / 1000000LL, ts % 1000000LL};
  */

  /* Windows FILETIME approach, has actual usec accuracy */
  /*
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  time_val::type_type tt = ft.dwHighDateTime;
  tt <<= 32;
  tt |= ft.dwLowDateTime;
  tt /= 10;
  tt -= 11644473600000000ULL;
  time_val tv_filetime{tt / 1000000LL, tt % 1000000LL};
  */

  return tv_systime;
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
