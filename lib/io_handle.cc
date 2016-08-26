#include "XXX/io_handle.h"

#include "XXX/io_loop.h"
#include "XXX/io_listener.h"
#include "XXX/log_macros.h"
#include "XXX/utils.h"

#include <memory>
#include <sstream>

#include <string.h>
#include <unistd.h>

namespace XXX {

struct write_req
{
  // C style polymorphism. The uv_write_t must be first member.
  uv_write_t req;
  uv_buf_t * bufs;
  size_t nbufs;

  write_req(size_t n)
  : bufs( new uv_buf_t[n] ),
    nbufs(n)
  {
  }

  ~write_req()
  {
    for (size_t i = 0; i < nbufs; i++)
      delete bufs[i].base;
    delete [] bufs;
  }

  write_req(const write_req&) = delete;
  write_req& operator=(const write_req&) = delete;
};


static void iohandle_alloc_buffer(uv_handle_t* /* handle */,
                                  size_t suggested_size,
                                  uv_buf_t* buf )
{
  // improve memory efficiency
  *buf = uv_buf_init((char *) new char[suggested_size], suggested_size);
}

/* Constructor */
io_handle::io_handle(kernel& k, uv_stream_t * hdl, io_loop * loop)
  : m_kernel(k),
    __logger(k.get_logger()),
    m_uv_handle(hdl),
    m_closed_handles_count(0),
    m_bytes_pending(0),
    m_bytes_written(0),
    m_bytes_read(0),
    m_pending_close_handles(false),
    m_shfut_io_closed(m_io_has_closed.get_future()),
    m_state(eOpen)
{
  /* IO thread */

  m_uv_handle->data = this;

  // set up the async handler
  uv_async_init(loop->uv_loop(), &m_write_async, [](uv_async_t* uvh){
      io_handle* ioh = static_cast<io_handle*>( uvh->data );
      ioh->write_async();
    });
  m_write_async.data = this;

}


void io_handle::start_read(std::shared_ptr<io_listener> p)
{
  m_listener = p;

  if (!m_uv_read_started)
  {
    uv_read_start(m_uv_handle, iohandle_alloc_buffer,
                  [](uv_stream_t*  uvh, ssize_t nread, const uv_buf_t* buf)
                  {
                    io_handle * iohandle = (io_handle *) uvh->data;
                    iohandle->on_read_cb(nread, buf);
                  });
    m_uv_read_started = true;
  }
}


io_handle::~io_handle()
{
  // Shutdown mutex has two purposes. [1] ensure shutdown-notifcation is fully
  // complete before commencing deletion, and [2] deterministically catch
  // attempt to delete self from the io_on_close callback (it will cause
  // deadlock).
  std::lock_guard<std::mutex> guard(m_shutdown_mtx);

  // If this object we can still be called by the IO thread, then a core dump or
  // other undefined behaviour will happen shortly.  Remove that uncertainty by
  // performing an immediate exit.
  if (m_state != eClosed)
  {
    LOG_ERROR("iohandle destructing without pior orderly shutdown - calling std::terminate");
    std::terminate();
  }

  delete m_uv_handle;

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    for (auto &i :m_pending_write ) delete [] i.base;
  }

}


void io_handle::on_close_cb()
{
  /* IO thread */

  if (++m_closed_handles_count == 2)
  {
    // while code still uses a shared_ptr to the observer (probably not the
    // right thing to do), make sure the target destructor (and hence self
    // destructor) does not get invoked during the shutdown critical section.
    auto sp = m_listener.lock();

    {
      std::lock_guard<std::mutex> guard(m_shutdown_mtx);

      // All our handles have been closed, so no more callbacks are due from the
      // IO service
      m_state = eClosed;

      if (sp)
      {
	      // Notify owning session about end of file event. The owner must not try
        // to delete this object from the current thread.
        sp->io_on_close();
        m_listener.reset();
      }

      // This must be final code in this method, because once called, this
      // object can be deleted immediately by another thread.
      m_io_has_closed.set_value();
    }
  }
}


void io_handle::write_async()
{
  /* IO thread */

  // Handling of close_handles signals needs to be checked first
  if (m_pending_close_handles)
  {
    // request closure of our UV handles
    uv_close((uv_handle_t*)&m_write_async, [](uv_handle_t* uvh){
        io_handle * h = (io_handle *) uvh->data;
        h->on_close_cb();
      });
    uv_close((uv_handle_t*)m_uv_handle,  [](uv_handle_t* uvh){
        io_handle * h = (io_handle *) uvh->data;
        h->on_close_cb();
      });

    return;
  }


  std::vector< uv_buf_t > copy;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap( copy );
  }

  size_t bytes_to_send=0;
  for (size_t i = 0; i < copy.size(); i++) bytes_to_send += copy[i].len;

  const size_t pend_max = m_kernel.get_config().socket_max_pending_write_bytes;

  if (m_state==eOpen && !copy.empty())
  {
    if (bytes_to_send > (pend_max - m_bytes_pending))
    {
      LOG_WARN("pending bytes limit reached; closing connection");
      init_close();
      return;
    }

    // build the request
    write_req* wr = new write_req(copy.size());
    wr->req.data = this;
    for (size_t i = 0; i < copy.size(); i++)
      wr->bufs[i] = copy[i];

    m_bytes_pending += bytes_to_send;

    int r = uv_write((uv_write_t*)wr, m_uv_handle, wr->bufs, wr->nbufs, [](uv_write_t * req, int status){
        io_handle * iohandle = (io_handle *) req->data;
        iohandle->on_write_cb(req, status);
      });

    if (r)
    {
      LOG_WARN("uv_write failed, errno " << std::abs(r)
               << " (" <<  uv_strerror(r) <<"); closing connection");
      delete wr;
      init_close();
      return;
    };

  }
}



void io_handle::write_bufs(std::pair<const char*, size_t> * srcbuf, size_t count, bool /*close*/)
{
  /* ANY thread */

  if (m_state != eOpen) return;

  std::vector< uv_buf_t > bufs;
  bufs.reserve(count);

  // improve memory usage here
  for (size_t i = 0; i < count ; i++)
  {
    uv_buf_t buf = uv_buf_init( new char[ srcbuf->second ], srcbuf->second);
    memcpy(buf.base, srcbuf->first, srcbuf->second);
    srcbuf++;
    bufs.push_back(buf);
  }


  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    if (m_state == eOpen)
    {
      m_pending_write.insert(m_pending_write.end(), bufs.begin(), bufs.end());
      bufs.clear();
      uv_async_send( &m_write_async );
    }
  }

  if (!bufs.empty())
    for (auto & i : bufs ) delete [] i.base;
}


/* User wants to initiate closure of the IO handle */
std::shared_future<void> io_handle::request_close()
{
  /* ANY thread */

  init_close();

  return m_shfut_io_closed;
}


void io_handle::init_close()
{
  /* IO thread */

  std::lock_guard<std::mutex> guard(m_pending_write_lock);

  if (m_state == eOpen)
  {
    m_state = eClosing;

    m_pending_close_handles = true;
    uv_async_send( &m_write_async );
  }
}


void io_handle::on_write_cb(uv_write_t * req, int status)
{
  /* IO thread */
  std::unique_ptr<write_req> wr ((write_req*) req); // ensure deletion

  try
  {
    if (status == 0)
    {
      size_t total = 0;
      for (size_t i = 0; i < req->nbufs; i++) total += req->bufsml[i].len;
      m_bytes_written += total;
      if (m_bytes_pending > total)
        m_bytes_pending -= total;
      else
        m_bytes_pending = 0;
    }
    else
    {
      // write failed - this can happen if we actively terminated the socket while
      // there were still a long queue of bytes awaiting output (eg inthe case of
      // a slow consumer)
      init_close();
    }
  }
  catch (...){log_exception(__logger, "IO thread in on_write_cb");}
}


void io_handle::on_read_cb(ssize_t nread ,
                          const uv_buf_t* buf)
{
  /* IO thread */

  try
  {
    if ((nread == UV_EOF) ||  (nread < 0))
    {
      init_close();
    }
    else if (nread > 0)
    {
      m_bytes_read += nread;
      if (auto sp = m_listener.lock()) sp->io_on_read(buf->base, nread);
    }
    else if (nread == 0)
    {
      // spinning?
    }
  }
  catch (...)
  {
    log_exception(__logger, "IO thread in on_read_cb");
    init_close();
  }

  delete [] buf->base;
}


int io_handle::fd() const
{
  return -1; // TODO:
}

} // namespace XXX
