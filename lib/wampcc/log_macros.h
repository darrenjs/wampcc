/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_LOG_MACROS_H
#define WAMPCC_LOG_MACROS_H

#include "wampcc/kernel.h"

#include <sstream>

#define LOGIMPL( X, LEVEL )                                             \
  do {                                                                  \
    if ( __logger.wants_level &&                                        \
         __logger.write &&                                              \
         __logger.wants_level(LEVEL) )                                  \
    {                                                                   \
      std::ostringstream __xx_oss;                                      \
      __xx_oss <<  X ;                                                  \
      __logger.write(LEVEL, __xx_oss.str(), __FILE__,__LINE__  ) ;      \
    }                                                                   \
  } while (0)

#define LOG_FOR_LEVEL( LEVEL )                                        \
  ( __logger.wants_level and                                          \
    __logger.write and                                                \
    __logger.wants_level(LEVEL))

#define LOG_INFO( X )                           \
  LOGIMPL( X, wampcc::logger::eInfo )

#define LOG_WARN( X )                           \
  LOGIMPL( X, wampcc::logger::eWarn )

#define LOG_ERROR( X )                          \
  LOGIMPL( X, wampcc::logger::eError )

#define LOG_DEBUG( X )                          \
  LOGIMPL( X, wampcc::logger::eDebug )

#define LOG_TRACE( X )                          \
  LOGIMPL( X, wampcc::logger::eTrace )


#endif
