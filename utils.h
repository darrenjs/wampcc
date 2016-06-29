#ifndef XXX_UTILS_H
#define XXX_UTILS_H

#include "logger.h"

#include <sstream>


#define THROW(E, X )  do                        \
  {                                             \
    std::ostringstream __os;                    \
    __os << X ;                                 \
    throw E ( __os.str() );                     \
  } while(false);


namespace XXX {

class logger;

enum class HMACSHA256_Mode
{
  HEX,
  BASE64
};

int compute_HMACSHA256(const char* key,
                       int keylen,
                       const char* msg,
                       int msglen,
                       char * dest,
                       unsigned int * destlen,
                       HMACSHA256_Mode output_mode);


/* must be called with an active exception */
void log_exception(logger *__logptr, const char* callsite);


} // namespace XXX

#endif
