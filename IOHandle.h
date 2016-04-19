#ifndef XXX_IOHANDLE_H
#define XXX_IOHANDLE_H

#include <uv.h>

#include <vector>
#include <mutex>

namespace XXX {

class Session;
class IOLoop;
class IOHandle;
class io_listener;
class Logger;


class IOHandle
{
public:
  IOHandle(Logger * logger, uv_stream_t * h, IOLoop * loop);
  ~IOHandle();

  IOHandle(const IOHandle&) = delete;
  IOHandle& operator=(const IOHandle&) = delete;


  void set_listener(io_listener* l ) { m_listener = l; }

  /* Enqueue bytes to be sent */
  void write_bufs(std::pair<const char*, size_t> * srcbuf, size_t count, bool close);

  void write_async_cb();

  // IO callbacks -- these get invoked on the IO thread
  void on_close();
  void on_read(char*, size_t);

  void on_passive_close();
  void active_close();

  bool can_be_deleted() const { return m_ready_for_delete; }

  void on_write_cb(uv_write_t * req, int status);
private:


  Logger * __logptr;

  // TODO: in destructor, need to close each of these handles.
  uv_stream_t* m_uv_handle;
  IOLoop* m_loop;
  bool m_open = true;

  uv_async_t   m_write_async;

  bool m_async_allowed = true;
  bool m_ready_for_delete = false;

  std::vector< uv_buf_t > m_pending_write;
  std::mutex              m_pending_write_lock;
  bool m_do_async_close = false;
  int m_close_count = 0;

  io_listener * m_listener;

  // TODO: make atomic
  size_t m_bytes_written = 0;
  size_t m_bytes_pending = 0; // pending written
};

} // namespace XXX

#endif
