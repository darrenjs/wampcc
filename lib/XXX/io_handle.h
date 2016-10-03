#ifndef XXX_IOHANDLE_H
#define XXX_IOHANDLE_H

#include <uv.h>

#include <vector>
#include <mutex>
#include <atomic>
#include <memory>
#include <future>

namespace XXX {

class io_loop;
class io_handle;
class io_listener;
struct logger;
class kernel;

class io_handle
{
public:
  io_handle(kernel&, uv_stream_t * h, io_loop * loop);
  ~io_handle();

  io_handle(const io_handle&) = delete;
  io_handle& operator=(const io_handle&) = delete;

  /* Enqueue bytes to be sent */
  void write_bufs(std::pair<const char*, size_t> * srcbuf, size_t count, bool final);

  std::shared_future<void> request_close();

  bool is_open() const { return m_state == eOpen; }

  void start_read(io_listener* p);

  /** Return underlying file description, for informational purposes. */
  int fd() const;

private:
  void write_async();

  void init_close();

  void on_write_cb(uv_write_t * req, int status);
  void on_read_cb(ssize_t, const uv_buf_t*);

  void do_close();
  void io_closed();

private:
  kernel & m_kernel;
  logger & __logger;

  uv_stream_t* m_uv_handle;
  uv_async_t   m_write_async;

  io_listener * m_listener;

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

  bool m_uv_read_started = false;
  friend io_loop;
};

} // namespace XXX

#endif
