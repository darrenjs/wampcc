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

  // {
  //   data = 0x0,
  //   type = UV_WRITE,
  //   active_queue = { 0x61800000fca0, 0x61800000fca0},
  //   reserved = {0x0, 0x0, 0x0, 0x0},
  //   cb = 0x5b2cd0 <XXX::io_on_write(uv_write_s*, int)>,
  //   send_handle = 0x0,
  //   handle = 0x611000009dc0,
  //   queue = {0x611000009e90, 0x611000009e90},
  //   write_index = 2,
  //   bufs = 0x0,
  //   nbufs = 2,
  //   error = 0,
  //   bufsml =
  //   {
  //     {base = 0x60200000cd10 "\001", len = 4},
  //     {base = 0x60700000a5f0 "\001", len = 76},
  //     {base = 0x0, len = 0}, {
  //     base = 0x0, len = 0}}}


static void __on_write_cb(uv_write_t * req, int status)
{
  IOHandle * iohandle = (IOHandle *) req->data;
  iohandle->on_write_cb(req, status);
}



// TODO: who allocated buf? I think it is on a stack somewhere.
static void __on_read_cb(uv_stream_t*  uvh,
                          ssize_t nread ,
                          const uv_buf_t* buf)
{
  IOHandle * iohandle = (IOHandle *) uvh->data;

  try
  {
    if ((nread == UV_EOF) ||  (nread < 0))
    {
      iohandle->on_passive_close();
    }
    else if (nread > 0)
    {
      iohandle->on_read(buf->base, nread);
    }
    else if (nread == 0)
    {
      // spinning?
    }
  }
  catch (...)
  {
    // TODO: catch excetion here? and close socket?  Should do this, just in
    // case an exception is thrown due to bad data ... dont want to keep reading
    // from the same bad data stream.
    std::cout << "caught exception during io callback\n";
  }

  delete [] buf->base;
}


static void iohandle_alloc_buffer(uv_handle_t* /* handle */,
                                  size_t suggested_size,
                                  uv_buf_t* buf )
{
  // TODO: not the most efficient
  *buf = uv_buf_init((char *) new char[suggested_size], suggested_size);
}

/* Constructor */
IOHandle::IOHandle(Logger * logger, uv_stream_t * h, IOLoop * loop)
  : __logptr(logger),
    m_uv_handle(h),
    m_loop(loop),
    m_open(true),
    m_listener( nullptr )
{
  h->data = this;

  // set up the async handler
  uv_async_init(loop->uv_loop(), &m_write_async, [](uv_async_t* uvh){
      IOHandle* ioh = static_cast<IOHandle*>( uvh->data );
      ioh->write_async_cb();
    });
  m_write_async.data = this;

  // enable for reading
   uv_read_start(h, iohandle_alloc_buffer, __on_read_cb);
}

/* Destructor */
IOHandle::~IOHandle()
{

  // Note, the assumption in here is that the socket will already have been
  // closed before this object is deleted.

  // // make last attempt to close the handle
  // if (!uv_is_closing((uv_handle_t *)m_uv_handle))
  //   uv_close((uv_handle_t *) m_uv_handle,  nullptr);

  delete m_uv_handle;


  // TODO: not sure I need these ... added when looking for a memory leak.  I
  // think I do need this, becuase without, I do get a lot of core dumps.
  // uv_close((uv_handle_t*)&m_write_async, nullptr);
  // uv_close((uv_handle_t*)&m_writeclose_async, nullptr);
  // uv_close((uv_handle_t*)&m_close_async, nullptr);


  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    for (auto &i :m_pending_write ) delete [] i.base;
  }
}

void IOHandle::on_close()
{
  /* IO thread */

  // we are ready for deletion once all our internal libuv handles are closed.
  if (++m_close_count == 2) m_ready_for_delete = true;
}

void IOHandle::on_read(char* buf, size_t len)
{
  /* IO thread */
  m_bytes_read += len;
  if (m_listener) m_listener->on_read(buf, len);
}



void IOHandle::write_async_cb()
{
  /* IO thread */

  if (m_do_async_close)
  {
    // request closure of our UV handles

    // TODO: not sure I need these ... added when looking for a memory leak.  I
    // think I do need this, becuase without, I do get a lot of core dumps.
    uv_close((uv_handle_t*)&m_write_async, [](uv_handle_t* uvh){
        IOHandle * h = (IOHandle *) uvh->data;
        h->on_close();
      });
    uv_close((uv_handle_t*)m_uv_handle,  [](uv_handle_t* uvh){
        IOHandle * h = (IOHandle *) uvh->data;
        h->on_close();
      });

    return;
  }

  bool do_termination = false;
  std::vector< uv_buf_t >  copy;

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap( copy );
    do_termination = !m_async_allowed;
  }

  size_t total_bytes=0;
  for (auto & item : copy) total_bytes += item.len;

  if (m_open)
  {
    if (!copy.empty())
    {
      // TODO: poor memory management!
      uv_write_t * req = new uv_write_t();
      memset(req,0,sizeof(uv_write_t));
      req->data = this;

      // TODO: need to handle these return types ... eg, if r indicates error,
      // we need to free req here. And probably close the connection,
      m_bytes_pending += total_bytes;

      std::cout << "PENDING: " << m_bytes_pending << "\n";
      int r = uv_write(req, m_uv_handle, &copy[0], copy.size(), __on_write_cb);
      if (r) delete req;

      // TODO: is this correcT? should we be freeing here?  NOOOO....
      for (auto &i : copy)  delete [] i.base;
    }
  }

  if (do_termination)
  {
    m_ready_for_delete = true;
    return;
  }

}


/*


NOTES:

uv_buf_t uv_buf_init(char* base, unsigned int len) {
  uv_buf_t buf;
  buf.base = base;
  buf.len = len;
  return buf;
}



 */


void IOHandle::on_passive_close()
{
  /* IO thread */

  // indicate we are closed at earliest oppurtunity
  m_open = false;

  // instruct listener never to call us again
  if (m_listener) m_listener->on_close(0);
  m_listener = nullptr;

  /* Raise an async request to close the socket.  This will be the last async
   * operation requested.  I.e., there will no more requests coming from the
   * Session object which owns this handle. */
  m_do_async_close = true;
  uv_async_send( &m_write_async );
}

// TODO: need to use the close variable
void IOHandle::write_bufs(std::pair<const char*, size_t> * srcbuf, size_t count, bool /*close*/)
{
  // TODO EASY: add DEBUG logging of the output data
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

  if (m_async_allowed)
  {
    uv_async_send( &m_write_async );
  }
}

void IOHandle::active_close()
{
  /* IO thread */

  // indicate we are closed at earliest oppurtunity
  m_open = false;

  // instruct listener never to call us again
  if (m_listener) m_listener->on_close(0);
  m_listener = nullptr;

  /* Raise an async request to close the socket.  This will be the last async
   * operation requested.  I.e., there will no more requests coming from the
   * Session object which owns this handle. */
  m_do_async_close = true;
  uv_async_send( &m_write_async );
}


void IOHandle::on_write_cb(uv_write_t * req, int status)
{
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
      std::cout << "ERROR: read status=" << status << "\n";
    }
  }
  catch (...){}


  // TODO: what should I be doing in here?

//   char *buffer = (char*) req->data;
// //  free(buffer);
//   delete [] buffer;

  delete req;
}

} // namespace XXX
