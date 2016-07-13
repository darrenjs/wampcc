#ifndef XXX_LOG_MACROS_H
#define XXX_LOG_MACROS_H

#include "kernel.h"

#include <sstream>

#define LOGIMPL( X, LEVEL )                                           \
  do {                                                                \
    if ( __log.wants_level and                                        \
         __log.write and                                              \
         __log.wants_level(LEVEL) )                                   \
    {                                                                 \
      std::ostringstream __xx_oss;                                    \
      __xx_oss <<  X ;                                                \
      __log.write(LEVEL, __xx_oss.str(), __FILE__,__LINE__  ) ;       \
    }                                                                 \
  } while (0)

#define LOG_INFO( X )                           \
  LOGIMPL( X, XXX::nlogger::eInfo )

#define LOG_WARN( X )                           \
  LOGIMPL( X, XXX::nlogger::eWarn )

#define LOG_ERROR( X )                          \
  LOGIMPL( X, XXX::nlogger::eError )

#define LOG_DEBUG( X )                          \
  LOGIMPL( X, XXX::nlogger::eDebug )

#endif
