#ifndef XXX_IOHANDLE_H
#define XXX_IOHANDLE_H

#include <uv.h>

#include <vector>
#include <mutex>
#include <atomic>

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

  void request_close();

  bool can_be_deleted() const;

private:
  void write_async();
  void init_close();

  void on_write_cb(uv_write_t * req, int status);
  void on_close_cb();
  void on_read_cb(uv_stream_t*, ssize_t, const uv_buf_t*);

private:
  Logger * __logptr;

  uv_stream_t* m_uv_handle;
  uv_async_t   m_write_async;

  IOLoop* m_loop;
  io_listener * m_listener;

  std::atomic<bool> m_is_closing;
  int m_closed_handles_count;

  std::atomic<size_t> m_bytes_pending; // pending written
  size_t m_bytes_written = 0;
  size_t m_bytes_read = 0;

  std::mutex              m_pending_write_lock;
  std::vector< uv_buf_t > m_pending_write;
  bool                    m_pending_close_handles;
  std::atomic<bool>       m_pending_call_close;
};

} // namespace XXX

#endif
