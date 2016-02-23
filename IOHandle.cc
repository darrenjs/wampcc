#include "IOHandle.h"


#include "IOLoop.h"
#include "Session.h"
#include "io_listener.h"

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


static void io_on_write(uv_write_t * req, int /*status*/)
{
  // TODO: what should I be doing in here?


  // std::cout << "on_write: status=" << (int)status
  //           << ", error=" << req->error << "\n";
  // if (status < 0 )
  // {
  //   std::cout << "failed\n";
  // }


//   // TODO: added this, but does not have any effect on memory growth of program
//   char *buffer = (char*) req->data;
// //  free(buffer);
//   delete [] buffer;

  delete req;
}

static void io_on_writeclose(uv_write_t *req, int status)
{
  std::cout << "on_writeclose: status=" << (int)status
            << ", error=" << req->error << "\n";
  if (status < 0 )
  {
    std::cout << "failed\n";
  }
  // make last attempt to close the handle
  if (!uv_is_closing((uv_handle_t *)req->handle))
    uv_close((uv_handle_t *) req->handle,  nullptr);

  delete req;
}

static void io_on_close2(uv_handle_t* handle)
{
  std::cout << "on_close2 handle=" << handle << "\n";
  IOHandle * iohandle = (IOHandle *) handle->data;
  iohandle->on_close();
}

static void io_on_close_cb(uv_handle_t* handle)
{
  IOHandle * iohandle = (IOHandle *) handle->data;
  iohandle->on_close();
}


// TODO: who allocated buf? I think it is on a stack somewhere.
static void io_on_read_cb(uv_stream_t*  uvh,
                          ssize_t nread ,
                          const uv_buf_t* buf)
{
//  std:: cout << "UV_EOF=" << UV_EOF << "\n"; 4095


  // TODO: this logging should go into the IO handle
  // std::ostringstream os;
  // for (int i = 0; i < nread; i++)
  // {

  //   char c = *(buf->base + i);
  //   if (isprint(c))
  //     os << c;
  //   else
  //     os << "(" << (unsigned int)c << ")";
  // }
  // std::cout << "recv, bytes: " << nread << ", data: " << os.str() << "\n";


  IOHandle * iohandle = (IOHandle *) uvh->data;

  try
  {
    if (nread < 0)
    {
      if (nread == UV_EOF)
      {
        std::cout << "got UV_EOF\n";
        // TODO: I should really call the IOHandler here
        //std::cout << "stream EOF\n";
      }
      iohandle->on_passive_close();
    }
    else if (nread > 0)
    {
      iohandle->on_read(buf->base, nread);
    }
  }
  catch (...)
  {
    std::cout << "caught exception during io callback\n";
  }

  //if (buf->len > 0)
  delete [] buf->base;
}

// TODO: crash error here, if this cb is invoked after handle has been deleted!
// need some kind of reference counter.
static void iohandle_write_async_cb(uv_async_t* handle)
{
  IOHandle* h = static_cast<IOHandle*>( handle->data );
  h->write_async_cb();
}

static void iohandle_writeclose_async_cb(uv_async_t* handle)
{
  IOHandle* h = static_cast<IOHandle*>( handle->data );
  h->writeclose_async_cb();
}

static void iohandle_close_async_cb(uv_async_t* handle)
{
  IOHandle* h = static_cast<IOHandle*>( handle->data );
  h->close_async_cb();
}

static void iohandle_alloc_buffer(uv_handle_t* /* handle */,
                                  size_t suggested_size,
                                  uv_buf_t* buf )
{
  // TODO: not the most efficient
  *buf = uv_buf_init((char *) new char[suggested_size], suggested_size);
}

/* Constructor */
IOHandle::IOHandle(uv_stream_t * h, IOLoop * loop)
  : m_uv_handle(h),
    m_loop(loop),
    m_open(true),
    m_listener( nullptr )
{
  h->data = this;

  // set up the async handler
  uv_async_init(loop->uv_loop(), &m_write_async, iohandle_write_async_cb);
  m_write_async.data = this;

  // set up the async handler
  uv_async_init(loop->uv_loop(), &m_writeclose_async, iohandle_writeclose_async_cb);
  m_writeclose_async.data = this;


  // set up the async handler
  uv_async_init(loop->uv_loop(), &m_close_async, iohandle_close_async_cb);
  m_close_async.data = this;

  // enable for reading
   uv_read_start(h, iohandle_alloc_buffer, io_on_read_cb);
}

/* Destructor */
IOHandle::~IOHandle()
{
  std::cout << "IOHandle::~IOHandle" << "\n";
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

void IOHandle::close(int)
{
  // request a UV callback, because we must invoke the UV close on the IO thread.
  uv_async_send( &m_close_async );
}



void IOHandle::on_close()
{
  /* IO thread */

  if (++m_close_count == 4) m_ready_for_delete = true;
}

void IOHandle::on_read(char* buf, size_t len)
{
  // TODO: catch excetion here? and close socket?
  if (m_listener) m_listener->on_read(buf, len);
}
/*



*/


void IOHandle::close_async_cb()
{
  /* called on the IO thread */

  std::cout << "user requested a close\n";
  // TODO: should set a pending here

  close_uv_handle();
  // if (m_open)
  // {
  //   if (uv_is_closing((uv_handle_t *)m_uv_handle))
  //   {
  //     std::cout << "socket is already closing, so skipping\n";
  //   }
   //   else
  //   {
  //     std::cout << "active close on " << this << "\n";
  //     uv_close((uv_handle_t *) m_uv_handle,  io_on_close2);
  //   }

  // }
}

void IOHandle::close_uv_handle()
{
  // // TODO: not sure I need to call uv_close if peer does the close
  // std::cout << "in close_uv_handle\n";
  // if (uv_is_closing((uv_handle_t *)m_uv_handle) == false)
  // {
  //   std::cout << "Called uv_close\n";
  //   uv_close((uv_handle_t *) m_uv_handle,  io_on_close2);
  // }
}



void IOHandle::write_async_cb()
{
  /* IO thread */

  if (m_do_async_close)
  {
    // request closure of our UV handles

    // TODO: not sure I need these ... added when looking for a memory leak.  I
    // think I do need this, becuase without, I do get a lot of core dumps.
    std::cout << "closing handles\n";
    uv_close((uv_handle_t*)&m_write_async, io_on_close_cb);
    uv_close((uv_handle_t*)&m_writeclose_async, io_on_close_cb);
    uv_close((uv_handle_t*)&m_close_async, io_on_close_cb);
    uv_close((uv_handle_t*)m_uv_handle, io_on_close_cb);

    return;
  }



//  std::cout << "write_async_cb\n";
  bool do_termination = false;
  std::vector< uv_buf_t >  copy;

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap( copy );
    do_termination = !m_async_allowed;
  }

  if (m_open)
  {
    // TODO: needs to be deleted
    uv_write_t * req = new uv_write_t();
    memset(req,0,sizeof(uv_write_t));

    // TODO: need to handle these return types ... eg, if r indicates error,
    // we need to free req here. And probably close the connection,
    if (copy.size())
      /*int r =*/ uv_write(req, m_uv_handle, &copy[0], copy.size(), io_on_write);
  }

  // TODO: is this correcT? should we be freeing here?  NOOOO....
  for (auto &i : copy)  delete [] i.base;

//  std::cout << "write_async_cb : m_async_allowed=" << m_async_allowed<< "\n";

  if (do_termination)
  {
    std::cout << "IOHandle is ready for termination\n";

    m_ready_for_delete = true;
    return;
  }

}

void IOHandle::writeclose_async_cb()
{
  /* called on the IO thread */

  /*
    NOTE : ONLY COMPLETE THIS FUNCTION ONCE THE VERY SIILAR ONCE (ABOVE) IS COMPLETE.
   */

  std::vector<uv_buf_t> copy;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    if (m_pending_write.empty()) return;

    m_pending_write.swap( copy );
  }

  // TODO: needs to be deleted
  uv_write_t * req = new uv_write_t();

  // TODO: need to handle these return types
  /*int r =*/ uv_write(req, m_uv_handle, &copy[0], copy.size(), io_on_writeclose);

  for (auto &item : copy)
  {
    delete item.base;
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



void IOHandle::send_bytes(const char* src, size_t len)
{
  static int i = 0;
//  std::cout << "msg count " << i++ << "\n";
  if (m_open)
  {
    // TODO: this is not an efficient way to manage buffer memory
    uv_buf_t buf = uv_buf_init( new char[ len ], len);
    memcpy(buf.base, src, len);

    {
      std::lock_guard<std::mutex> guard(m_pending_write_lock);
      m_pending_write.push_back( buf );

      if (m_async_allowed)
      {
        uv_async_send( &m_write_async );
      }
    }

  }
}


void IOHandle::send_bytes_close(const char* src, size_t len)
{
  // TODO: this is not an efficient way to manage buffer memory
  uv_buf_t buf = uv_buf_init( new char[ len ], len);
  memcpy(buf.base, src, len);

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.push_back( buf );

    if (m_async_allowed)
    {
      uv_async_send( &m_write_async );
    }
  }

}


void IOHandle::on_passive_close()
{
  /* IO thread */

  std::cout << "on_passive_close\n";

  // indicate we are closed at earliest oppurtunity
  m_open = false;

  // instruct listener never to call us again
  if (m_listener) m_listener->on_close(0);

  // raise an async request to close the socket
  m_do_async_close = true;
  uv_async_send( &m_write_async );



  // // close the UV handle
  // if (! uv_is_closing((uv_handle_t *) m_uv_handle) )
  // {
  //   std::cout << "going into uv_close\n";
  //   uv_close((uv_handle_t*)m_uv_handle, io_on_close_cb); // TODO: not sure about io_on_close here
  // }


  // // raise the last async operation
  // {
  //   std::lock_guard<std::mutex> guard(m_pending_write_lock);

  //   if (!m_async_pending && m_async_allowed)
  //   {
  //     // std::cout << "raised async\n";
  //     m_async_pending = true;
  //     uv_async_send( &m_write_async );
  //   }
  //   else
  //   {
  //     // std::cout << "not raised\n";
  //   }
  //   m_async_allowed = false;
  // }

}



} // namespace XXX
