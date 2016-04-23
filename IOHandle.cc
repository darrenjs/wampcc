#include "IOHandle.h"


#include "IOLoop.h"
#include "Session.h"
#include "io_listener.h"
#include "Logger.h"

#include <iostream>
#include <memory>
#include <sstream>

#include <string.h>

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
    delete [] bufs;
  }
};


static void iohandle_alloc_buffer(uv_handle_t* /* handle */,
                                  size_t suggested_size,
                                  uv_buf_t* buf )
{
  // TODO: not the most efficient
  *buf = uv_buf_init((char *) new char[suggested_size], suggested_size);
}

/* Constructor */
IOHandle::IOHandle(Logger * logger, uv_stream_t * hdl, IOLoop * loop)
  : __logptr(logger),
    m_uv_handle(hdl),
    m_loop(loop),
    m_listener( nullptr ),
    m_open(true),
    m_closed_handles_count(0),
    m_bytes_pending(0),
    m_bytes_written(0),
    m_bytes_read(0)
{
  m_uv_handle->data = this;

  // set up the async handler
  uv_async_init(loop->uv_loop(), &m_write_async, [](uv_async_t* uvh){
      IOHandle* ioh = static_cast<IOHandle*>( uvh->data );
      ioh->write_async();
    });
  m_write_async.data = this;

  // enable for reading
  uv_read_start(m_uv_handle, iohandle_alloc_buffer,
                [](uv_stream_t*  uvh, ssize_t nread, const uv_buf_t* buf)
                {
                  IOHandle * iohandle = (IOHandle *) uvh->data;
                  iohandle->on_read_cb(uvh, nread, buf);
                });
}


/* Destructor */
IOHandle::~IOHandle()
{
  // Note, the assumption in here is that the socket will already have been
  // closed before this object is deleted.

  delete m_uv_handle;

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    for (auto &i :m_pending_write ) delete [] i.base;
  }
}


void IOHandle::on_close_cb()
{
  /* IO thread */

  m_closed_handles_count++ ;
}


bool IOHandle::can_be_deleted() const
{
  // we are ready for deletion once all our internal libuv handles are closed
  return m_closed_handles_count >= 2;
}


void IOHandle::write_async()
{
  /* IO thread */

  if (m_do_async_close)
  {
    // request closure of our UV handles

    // TODO: not sure I need these ... added when looking for a memory leak.  I
    // think I do need this, becuase without, I do get a lot of core dumps.
    uv_close((uv_handle_t*)&m_write_async, [](uv_handle_t* uvh){
        IOHandle * h = (IOHandle *) uvh->data;
        h->on_close_cb();
      });
    uv_close((uv_handle_t*)m_uv_handle,  [](uv_handle_t* uvh){
        IOHandle * h = (IOHandle *) uvh->data;
        h->on_close_cb();
      });

    return;
  }

  std::vector< uv_buf_t >  copy;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap( copy );
  }

  size_t bytes_to_send=0;
  for (size_t i = 0; i < copy.size(); i++) bytes_to_send += copy[i].len;

  static size_t PENDING_MAX = 1 * 1000000;

  if (m_open && !copy.empty())
  {
    if (bytes_to_send > (PENDING_MAX - m_bytes_pending))
    {
      // oh dear, we have to now close this connection
      _WARN_("pending bytes limit reached; closing connection");
      close_async();
      return;
    }

    // build the request
    write_req* wr = new write_req(copy.size());
    wr->req.data = this;
    for (size_t i = 0; i < copy.size(); i++)
      wr->bufs[i] = copy[i];

    m_bytes_pending += bytes_to_send;
    //if (m_bytes_pending>10000)  std::cout << "PENDING: " << m_bytes_pending << "\n";
    // TODO: need to handle these return types ... eg, if r indicates error,
    // we need to free req here. And probably close the connection,

    int r = uv_write((uv_write_t*)wr, m_uv_handle, wr->bufs, wr->nbufs, [](uv_write_t * req, int status){
        IOHandle * iohandle = (IOHandle *) req->data;
        iohandle->on_write_cb(req, status);
      });

    if (r) delete wr; // TODO: also, close the connection?

  }
}


// TODO: need to use the close variable
void IOHandle::write_bufs(std::pair<const char*, size_t> * srcbuf, size_t count, bool /*close*/)
{
  /* ANY thread */

  std::vector< uv_buf_t > bufs;
  bufs.reserve(count);

  // TODO: this is not an efficient way to manage buffer memory
  for (size_t i = 0; i < count ; i++)
  {
    uv_buf_t buf = uv_buf_init( new char[ srcbuf->second ], srcbuf->second);
    memcpy(buf.base, srcbuf->first, srcbuf->second);
    srcbuf++;
    bufs.push_back(buf);
  }

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.insert(m_pending_write.end(), bufs.begin(), bufs.end());
  }

  uv_async_send( &m_write_async );
}


void IOHandle::close_async()
{
  /* IO thread  --- and maybe EV ???? */

  if ( !m_open ) return;

  // indicate we are closed at earliest oppurtunity
  m_open = false;

  // instruct listener/owner never to call us again, to prevent it sending new
  // output requests after the close request
  if (m_listener) m_listener->on_close();
  m_listener = nullptr;

  /* Raise an async request to close the socket.  This will be the last async
   * operation requested.  I.e., there will no more requests coming from the
   * Session object which owns this handle. */
  m_do_async_close = true;
  uv_async_send( &m_write_async );
}


void IOHandle::on_write_cb(uv_write_t * req, int status)
{
  /* IO thread */

  try
  {

    if (status == 0)
    {
      size_t total = 0;
      for (size_t i = 0; i < req->nbufs; i++)
      {
        total += req->bufsml[i].len;
      }
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
      close_async();
    }
  }
  catch (...){}

  write_req* wr = (write_req*) req;
  delete wr;
}


void IOHandle::on_read_cb(uv_stream_t*  uvh,
                          ssize_t nread ,
                          const uv_buf_t* buf)
{
  /* IO thread */

  try
  {
    if ((nread == UV_EOF) ||  (nread < 0))
    {
      close_async();
    }
    else if (nread > 0)
    {
      m_bytes_read += nread;
      if (m_listener) m_listener->on_read(buf->base, nread);
    }
    else if (nread == 0)
    {
      // spinning?
    }
  }
  catch (...)
  {
    close_async();
  }

  delete [] buf->base;
}


} // namespace XXX
