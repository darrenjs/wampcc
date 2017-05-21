/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_PLATFORM_H
#define WAMPCC_PLATFORM_H

#include <string>

#ifndef _WIN32
#include <sys/time.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
  #define snprintf _snprintf
  #define vsnprintf _vsnprintf
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp
#endif

namespace wampcc {

  struct time_val {
    long  sec;        /* seconds */
    long  usec;       /* micros */
  };

  int thread_id();

  std::string local_timestamp();

  wampcc::time_val time_now();

  /** Return local hostname, or throw upon failure. */
  std::string hostname();

} // namespace

#endif
