#ifndef XXX_LOG_MACROS_H
#define XXX_LOG_MACROS_H

#include "kernel.h"

#include <sstream>

#define LOGIMPL( X, LEVEL )                                           \
  do {                                                                \
    if ( __logger.wants_level and                                        \
         __logger.write and                                              \
         __logger.wants_level(LEVEL) )                                   \
    {                                                                 \
      std::ostringstream __xx_oss;                                    \
      __xx_oss <<  X ;                                                \
      __logger.write(LEVEL, __xx_oss.str(), __FILE__,__LINE__  ) ;       \
    }                                                                 \
  } while (0)

#define LOG_INFO( X )                           \
  LOGIMPL( X, XXX::logger::eInfo )

#define LOG_WARN( X )                           \
  LOGIMPL( X, XXX::logger::eWarn )

#define LOG_ERROR( X )                          \
  LOGIMPL( X, XXX::logger::eError )

#define LOG_DEBUG( X )                          \
  LOGIMPL( X, XXX::logger::eDebug )

#endif
