#ifndef XXX_IO_LISTENER_H
#define XXX_IO_LISTENER_H

#include <cstddef>

namespace XXX {

class io_listener
{
public:
  virtual ~io_listener() {}

  /* On EOF, ssize_t value will be -1 */
  virtual void io_on_read(char*, ssize_t)  = 0;
};

} // namespace

#endif
