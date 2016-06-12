#ifndef XXX_IOHANDLE_H
#define XXX_IOHANDLE_H

#include <uv.h>

#include <vector>
#include <mutex>
#include <atomic>
#include <memory>
#include <future>

namespace XXX {

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

  /* Enqueue bytes to be sent */
  void write_bufs(std::pair<const char*, size_t> * srcbuf, size_t count, bool final);

  std::shared_future<void> request_close();

  bool is_open() const { return m_state == eOpen; }

  /** Starting from socket. This should only be called once. */
  void start_read(std::shared_ptr<io_listener> p);

private:
  void write_async();

  void init_close();

  void on_write_cb(uv_write_t * req, int status);
  void on_close_cb();
  void on_read_cb(ssize_t, const uv_buf_t*);

private:
  Logger * __logptr;

  uv_stream_t* m_uv_handle;
  uv_async_t   m_write_async;

  std::weak_ptr<io_listener> m_listener;

  int m_closed_handles_count;

  std::atomic<size_t> m_bytes_pending; // pending written
  size_t m_bytes_written = 0;
  size_t m_bytes_read = 0;

  std::mutex              m_pending_write_lock;
  std::vector< uv_buf_t > m_pending_write;
  bool                    m_pending_close_handles;

  std::promise<void>       m_io_has_closed;
  std::shared_future<void> m_shfut_io_closed;

  enum State
  {
    eOpen,
    eClosing,
    eClosed
  };
  State m_state;

};

} // namespace XXX

#endif
