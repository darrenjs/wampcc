#include <XXX/tcp_socket.h>
#include <XXX/kernel.h>
#include <XXX/io_loop.h>
#include <XXX/io_listener.h>
#include <XXX/log_macros.h>
#include <XXX/utils.h>

#include <iostream>

using namespace std;

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


tcp_socket::tcp_socket(kernel* k, uv_tcp_t* h, socket_state ss)
  : m_kernel(k),
    __logger(k->get_logger()),
    m_uv_tcp( h ),
    m_state(ss),
    m_io_closed_future(m_io_closed_promise.get_future()),
    m_bytes_pending_write(0),
    m_bytes_written(0),
    m_bytes_read(0),
    m_listener(nullptr)
{
  if (ss == e_init)
    uv_tcp_init(m_kernel->get_io()->uv_loop(), m_uv_tcp);

  m_uv_tcp->data = new uv_handle_data(uv_handle_data::e_tcp_socket, this);
}


tcp_socket::tcp_socket(kernel* k)
  : tcp_socket(k, new uv_tcp_t(), e_init)
{
}


tcp_socket::tcp_socket(kernel* k, uv_tcp_t* s)
  : tcp_socket(k, s, e_connected)
{
}


tcp_socket::~tcp_socket()
{
  {
    std::unique_lock<std::mutex> guard(m_state_lock);
    if ((m_state != e_closing) && (m_state != e_closed))
    {
      m_state = e_closing;

      // TODO: what if this throws? At the minimum, we should catch it, which
      // would imply the IO thread is in the process of shutting down.  During
      // its shutdown, it should eventually delete the socket, so we should
      // continue to wait.
      try {
        m_kernel->get_io()->push_fn( [this](){ this->do_close(); } );
      } catch (...) {
        // TODO: log a warning here
        cout << "tcp_socket unable to request close, is io_loop already stopped?";
      }
    }
  }

  m_io_closed_future.wait();

  uv_handle_data * ptr = (uv_handle_data *) m_uv_tcp->data;
  delete ptr;

  delete m_uv_tcp;

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    for (auto &i :m_pending_write ) delete [] i.base;
  }
}


bool tcp_socket::is_listening() const
{
  std::unique_lock<std::mutex> guard(m_state_lock);
  return m_state == e_listening;
}

bool tcp_socket::is_connected() const
{
  std::unique_lock<std::mutex> guard(m_state_lock);
  return m_state == e_connected;
}


bool tcp_socket::is_closing() const
{
  std::unique_lock<std::mutex> guard(m_state_lock);
  return m_state == e_closing;
}


bool tcp_socket::is_closed() const
{
  std::unique_lock<std::mutex> guard(m_state_lock);
  return m_state == e_closed;
}


std::future<void> tcp_socket::connect(std::string addr, int port)
{
  bool resolve_hostname = true;

  auto completion_promise = std::make_shared<std::promise<void>>();

  auto success_fn = [completion_promise,this]() {
    {
      /* IO thread */
      std::unique_lock<std::mutex> guard(m_state_lock);
      if (m_state == e_init)
        m_state = e_connected;
    }
    completion_promise->set_value();
  };

  auto failure_fn = [completion_promise,this](std::exception_ptr e) {
    /* IO thread */
    completion_promise->set_exception( e );
  };

  // std::unique_lock<std::mutex> guard(sp->m_mutex);
  m_kernel->get_io()->connect(m_uv_tcp,
                              addr,
                              std::to_string(port),
                              resolve_hostname,
                              success_fn,
                              failure_fn);


  return completion_promise->get_future();
}


void tcp_socket::connect(std::string addr, int port, on_connect_cb user_cb)
{
  bool resolve_hostname = true;


  auto success_fn = [user_cb,this]() {
    {
      std::unique_lock<std::mutex> guard(m_state_lock);
      if (m_state == e_init)
        m_state = e_connected;
    }
    user_cb(this,0);
  };

  auto failure_fn = [user_cb,this](std::exception_ptr e) {
    user_cb(this,1);
  };

  // std::unique_lock<std::mutex> guard(sp->m_mutex);
  m_kernel->get_io()->connect(m_uv_tcp,
                              addr,
                              std::to_string(port),
                              resolve_hostname,
                              success_fn,
                              failure_fn);
}


void tcp_socket::do_close()
{
  /* IO thread */

  // do_close should only ever be called once by the IO thread, either triggered
  // by pushing a close request or a call from uv_walk.
  {
    std::lock_guard< std::mutex > guard (m_state_lock);
    m_state = e_closing;
  }

  uv_close((uv_handle_t*) m_uv_tcp, [](uv_handle_t * h) {

      uv_handle_data * ptr = (uv_handle_data*) h->data;
      tcp_socket * sock = ptr->tcp_socket_ptr();

      on_close_cb user_close_fn = std::move(sock->m_user_close_fn);

      {
        std::lock_guard< std::mutex > guard (sock->m_state_lock);
        sock->m_state = e_closed;
      }

      /* Careful ... once the promise is set, this object might be immediately
       * deleted by a thread waiting on the associated future. So make this
       * promise-write the last action. */
      sock->m_io_closed_promise.set_value();

      if (user_close_fn)
        user_close_fn();
    });
}


int tcp_socket::fd() const
{
  return m_uv_tcp->io_watcher.fd;
}


/** User request to close socket */
std::shared_future<void> tcp_socket::close()
{
  std::lock_guard< std::mutex > guard (m_state_lock);

  if (m_state == e_closing || m_state == e_closed)
    throw std::runtime_error("socket closing or closed");

  m_state = e_closing;
  m_kernel->get_io()->push_fn( [this]() {
      this->do_close();
    });

  return m_io_closed_future;
}


bool tcp_socket::close(on_close_cb user_on_close_fn)
{
  std::lock_guard< std::mutex > guard (m_state_lock);

  // if socket has already been closed, it will not be possible to invoke the
  // user on_close callback
  if (m_state == e_closed)
    return false;

  m_user_close_fn = user_on_close_fn;

  // push the close event ... this might throw if the IO loop is in processing
  // of stopping
  if (m_state != e_closing)
    try {
      // TODO: there might be other cases of throw, eg, memory
      m_kernel->get_io()->push_fn( [this]() { this->do_close(); });
      m_state = e_closing;
    }
    catch (...) { // TODO: capture exact exception type
      LOG_WARN("cannot push tcp_socket close request; has kernel already stopped?");
    }

  return true;
}


void tcp_socket::start_read(io_listener* p)
{
  m_listener = p;

  auto fn = [this]() {
    // TODO: check return result, and return to user
    uv_read_start((uv_stream_t*)this->m_uv_tcp,
                  iohandle_alloc_buffer,
                  [](uv_stream_t* uvh, ssize_t nread, const uv_buf_t* buf) {
                    uv_handle_data * ptr = (uv_handle_data*) uvh->data;
                    ptr->tcp_socket_ptr()->on_read_cb(nread, buf);
                  });
  };

  std::lock_guard< std::mutex > guard (m_state_lock);
  if (m_state == e_closing || m_state == e_closed)
    throw std::runtime_error("socket closing or closed");

  m_kernel->get_io()->push_fn( std::move(fn) );
}


/* Push a close event, but unlike the user facing function 'close', does not
 * throw an exception if already has been requested to close.
 */
void tcp_socket::close_once_on_io()
{
  /* IO thread */

  std::lock_guard< std::mutex > guard (m_state_lock);
  if (m_state != e_closing && m_state != e_closed)
  {
    m_state = e_closing;
    m_kernel->get_io()->push_fn( [this](){ this->do_close(); } );
  }
}


void tcp_socket::on_read_cb(ssize_t nread, const uv_buf_t* buf)
{
  /* IO thread */

  if (nread>0)
    m_bytes_read += nread;

  try
  {
    if ((nread == UV_EOF) ||  (nread < 0))
    {
      if (m_listener)
        m_listener->io_on_read(nullptr, -1);
    }
    else
    {
      if (m_listener)
        m_listener->io_on_read(buf->base, nread);
    }
  }
  catch (...)
  {
    log_exception(__logger, "IO thread in on_read_cb");
  }


  delete [] buf->base;
}


void tcp_socket::write(std::pair<const char*, size_t> * srcbuf, size_t count)
{
  // improve memory usage here
  std::vector< uv_buf_t > bufs;

  scope_guard buf_guard([&bufs]() {
      for (auto & i : bufs ) delete [] i.base;
    });

  bufs.reserve(count);
  for (size_t i = 0; i < count ; i++)
  {
    uv_buf_t buf = uv_buf_init( new char[ srcbuf->second ], srcbuf->second);
    memcpy(buf.base, srcbuf->first, srcbuf->second);
    srcbuf++;
    bufs.push_back(buf);
  }

  // synchronised section
  {
    std::lock_guard< std::mutex > guard (m_state_lock);
    if (m_state == e_closing || m_state == e_closed)
      throw std::runtime_error("socket closing or closed");

    {
      std::lock_guard<std::mutex> guard(m_pending_write_lock);
      m_pending_write.insert(m_pending_write.end(), bufs.begin(), bufs.end());
      bufs.clear();
      buf_guard.dismiss();
    }

    m_kernel->get_io()->push_fn( [this](){ this->do_write(); } );
  }
}


void tcp_socket::do_write()
{
  /* IO thread */

  std::vector< uv_buf_t > copy;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap( copy );
  }

  size_t bytes_to_send=0;
  for (size_t i = 0; i < copy.size(); i++)
    bytes_to_send += copy[i].len;

  const size_t pend_max = m_kernel->get_config().socket_max_pending_write_bytes;

  if (is_connected() && !copy.empty())
  {
    if (bytes_to_send > (pend_max - m_bytes_pending_write))
    {
      LOG_WARN("pending bytes limit reached; closing connection");
      close_once_on_io();
      return;
    }

    // build the request
    write_req* wr = new write_req(copy.size());
    wr->req.data = this;
    for (size_t i = 0; i < copy.size(); i++)
      wr->bufs[i] = copy[i];

    m_bytes_pending_write += bytes_to_send;

    int r = uv_write((uv_write_t*)wr, (uv_stream_t*) m_uv_tcp, wr->bufs, wr->nbufs, [](uv_write_t * req, int status){
        tcp_socket* the_tcp_socket = (tcp_socket*) req->data;
        the_tcp_socket->on_write_cb(req, status);
      });

    if (r)
    {
      LOG_WARN("uv_write failed, errno " << std::abs(r)
               << " (" <<  uv_strerror(r) <<"); closing connection");
      delete wr;
      close_once_on_io();
      return;
    };

  }
}


void tcp_socket::on_write_cb(uv_write_t * req, int status)
{
  /* IO thread */

  std::unique_ptr<write_req> wr ((write_req*) req); // ensure deletion

  try
  {
    if (status == 0)
    {
      size_t total = 0;
      for (size_t i = 0; i < req->nbufs; i++)
        total += req->bufsml[i].len;

      m_bytes_written += total;
      if (m_bytes_pending_write > total)
        m_bytes_pending_write -= total;
      else
        m_bytes_pending_write = 0;
    }
    else
    {
      // write failed - this can happen if we actively terminated the socket while
      // there were still a long queue of bytes awaiting output (eg inthe case of
      // a slow consumer)
      close_once_on_io();
    }
  }
  catch (...){log_exception(__logger, "IO thread in on_write_cb");}
}


void tcp_socket::on_listen_cb(int status)
{
  /* IO thread */

  if (status < 0)
  {
    // TODO: convert from UV to system error code
    if (m_user_accept_fn)
    {
      std::unique_ptr<tcp_socket> no_socket;
      m_user_accept_fn(this, no_socket, status);
    }
    return;
  }

  uv_tcp_t *client = new uv_tcp_t();
  uv_tcp_init(m_kernel->get_io()->uv_loop(), client);

  int r = uv_accept((uv_stream_t*) m_uv_tcp, (uv_stream_t*) client);
  if (r == 0)
  {
    std::unique_ptr<tcp_socket> new_sock (new tcp_socket(m_kernel, client));

    // TODO: convert from UV to system error code
    if (m_user_accept_fn)
      m_user_accept_fn(this, new_sock, r);

    if (new_sock)
    {
      tcp_socket * ptr = new_sock.release();
      ptr->close([ptr]() {
          delete ptr;
        });
    }

  }
  else
  {
    uv_close((uv_handle_t *) client, [](uv_handle_t * h){ delete h; });
  }

}


void tcp_socket::do_listen(int port, std::shared_ptr<std::promise<int>> sp_promise)
{
  /* IO thread */


  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", port, &addr);

  unsigned flags = 0;
  int r;


  r = uv_tcp_bind(m_uv_tcp, (const struct sockaddr*)&addr, flags);

  if (r == 0)
    r = uv_listen( (uv_stream_t*) m_uv_tcp, 5, [](uv_stream_t* server, int status) {
        uv_handle_data* uvhd_ptr = (uv_handle_data*) server->data;
        uvhd_ptr->tcp_socket_ptr()->on_listen_cb(status);
      });

  if (r==0)
  {
    std::lock_guard< std::mutex > guard (m_state_lock);
    if (m_state == e_init)
      m_state = e_listening;
  }
  // TODO: covert from UV to system error code
  sp_promise->set_value(r);

}


std::future<int> tcp_socket::listen(int port, on_accept_cb user_fn)
{
  m_user_accept_fn = std::move(user_fn);

  auto completion_promise = std::make_shared<std::promise<int>>();

  {
    std::lock_guard< std::mutex > guard (m_state_lock);
    if (m_state == e_closing || m_state == e_closed)
      throw std::runtime_error("socket closing or closed");

    m_kernel->get_io()->push_fn( [this,port,completion_promise](){
        this->do_listen(port, completion_promise);
      } );
  }

  return completion_promise->get_future();
}


} // namespace XXX
