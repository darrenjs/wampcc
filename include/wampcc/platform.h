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

#ifdef _WIN32
  #define snprintf _snprintf
  #define vsnprintf _vsnprintf
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp

  // VC++ doesn't define ssize_t, so follow definition used by libuv
  #if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
    typedef intptr_t ssize_t;
    #define _SSIZE_T_
    #define _SSIZE_T_DEFINED
  #endif
#endif

namespace wampcc
{

  struct time_val
  {
#ifndef _WIN32
    typedef long type_type;
#else
    typedef __time64_t type_type;
#endif
    type_type sec;  /* seconds */
    type_type usec; /* micros */
  };

  int thread_id();

  wampcc::time_val time_now();

  /** Return local hostname, or throw upon failure. */
  std::string hostname();

} // namespace

#endif
