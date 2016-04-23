#ifndef XXX_IO_LISTENER_H
#define XXX_IO_LISTENER_H

namespace XXX {

class IOHandle;

class io_listener
{
public:
  virtual ~io_listener() {}

  virtual void on_close() = 0; // on this calls, the handle is invalidated
  virtual void on_read(char*, size_t)  = 0;
};

} // namespace

#endif
