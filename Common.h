#ifndef __COMMON_H_
#define __COMMON_H_

#include <sstream>


#define THROW(E, X )  do                        \
  {                                             \
    std::ostringstream __os;                    \
    __os << X ;                                 \
    throw E ( __os.str() );                     \
  } while(false);

namespace XXX
{



}; // namepsace

#endif
