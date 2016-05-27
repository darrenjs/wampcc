#ifndef XXX_UTILS_H
#define XXX_UTILS_H

#include "Logger.h"

#include <sstream>


#define THROW(E, X )  do                        \
  {                                             \
    std::ostringstream __os;                    \
    __os << X ;                                 \
    throw E ( __os.str() );                     \
  } while(false);


// TODO: make an enum
#define HMACSHA256_HEX    0
#define HMACSHA256_BASE64 2

namespace XXX {

class Logger;

int compute_HMACSHA256(const char* key,
                       int keylen,
                       const char* msg,
                       int msglen,
                       char * dest,
                       unsigned int * destlen,
                       int output_mode);


/* must be called with an active exception */
void log_exception(Logger *__logptr, const char* callsite);


} // namespace XXX

#endif
