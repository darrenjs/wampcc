#ifndef XXX_IO_LISTENER_H
#define XXX_IO_LISTENER_H

#include <cstddef>

namespace XXX {

class IOHandle;

class io_listener
{
public:
  virtual ~io_listener() {}

  /* Following this call, IO handle is invalidated and must not be used again */
  virtual void io_on_close() = 0;

  virtual void io_on_read(char*, size_t)  = 0;
};

} // namespace

#endif
