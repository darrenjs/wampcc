/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/tcp_socket.h"
#include "wampcc/kernel.h"
#include "wampcc/io_loop.h"
#include "wampcc/log_macros.h"
#include "wampcc/utils.h"

#include <iostream>

#include <assert.h>

namespace wampcc
{

struct write_req
{
  // C style polymorphism. The uv_write_t must be first member.
  uv_write_t req;
  uv_buf_t* bufs;
  size_t nbufs;

  write_req(size_t n) : bufs(new uv_buf_t[n]), nbufs(n) {}

  ~write_req()
  {
    for (size_t i = 0; i < nbufs; i++)
      delete bufs[i].base;
    delete[] bufs;
  }

  write_req(const write_req&) = delete;
  write_req& operator=(const write_req&) = delete;
};


static void iohandle_alloc_buffer(uv_handle_t* /* handle */,
                                  size_t suggested_size, uv_buf_t* buf)
{
  // improve memory efficiency
  *buf = uv_buf_init((char*)new char[suggested_size], suggested_size);
}


tcp_socket::tcp_socket(kernel* k, uv_tcp_t* h, socket_state ss)
  : m_kernel(k),
    __logger(k->get_logger()),
    m_uv_tcp(h),
    m_state(ss),
    m_io_closed_promise(new std::promise<void>),
    m_io_closed_future(m_io_closed_promise->get_future()),
    m_bytes_pending_write(0),
    m_bytes_written(0),
    m_bytes_read(0)
{
  if (m_uv_tcp)
    m_uv_tcp->data = new uv_handle_data(this);
}


tcp_socket::tcp_socket(kernel* k)
  : tcp_socket(k, nullptr, socket_state::uninitialised)
{
}


tcp_socket::~tcp_socket()
{
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if ((m_state != socket_state::closing) &&
        (m_state != socket_state::closed)) {
      m_state = socket_state::closing;

      // TODO: what if this throws? At the minimum, we should catch it, which
      // would imply the IO thread is in the process of shutting down.  During
      // its shutdown, it should eventually delete the socket, so we should
      // continue to wait.  Note, there is a later wait, but that should only be
      // called if the push suceeded (ie, did not throw an exception).  Also,
      // need to consider what thread we might be on; add a test case for being
      // on the IO thread.
      try {
        m_kernel->get_io()->push_fn([this]() { this->do_close(); });
      } catch (io_loop_closed& e) {
        LOG_WARN("cannot push tcp_socket close request; has kernel already "
                 "stopped?");
      }
    }
  }

  // TODO: this would block, if we are on the IO thread!!!
  if (not is_closed())
    m_io_closed_future.wait();

  if (m_uv_tcp) {
    uv_handle_data* ptr = (uv_handle_data*)m_uv_tcp->data;
    delete ptr;
    delete m_uv_tcp;
  }

  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    for (auto& i : m_pending_write)
      delete[] i.base;
  }
}


bool tcp_socket::is_listening() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == socket_state::listening;
}

bool tcp_socket::is_connected() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == socket_state::connected;
}


bool tcp_socket::is_closing() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == socket_state::closing;
}


bool tcp_socket::is_closed() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == socket_state::closed;
}


std::future<uverr> tcp_socket::connect(std::string addr, int port)
{
  {
    std::lock_guard<std::mutex> guard(m_state_lock);

    if (m_state != socket_state::uninitialised)
      throw tcp_socket::error("connect(): tcp_socket already initialised");

    m_state = socket_state::connecting;
  }

  assert(m_uv_tcp == nullptr);
  m_uv_tcp = new uv_tcp_t;
  uv_tcp_init(m_kernel->get_io()->uv_loop(), m_uv_tcp);
  m_uv_tcp->data = new uv_handle_data(this);

  bool resolve_hostname = true;

  auto completion_promise = std::make_shared<std::promise<uverr>>();

  auto result_fn = [completion_promise, this](uverr ec) {
    /* IO thread */
    if (!ec) {
      std::lock_guard<std::mutex> guard(m_state_lock);
      m_state = socket_state::connected;
    }
    completion_promise->set_value(ec);
  };

  m_kernel->get_io()->connect(m_uv_tcp, addr, std::to_string(port),
                              resolve_hostname, result_fn);

  return completion_promise->get_future();
}


void tcp_socket::do_close(bool no_linger)
{
  /* IO thread */

  // this method should only ever be called once by the IO thread, either
  // triggered by pushing a close request or a call from uv_walk.
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    m_state = socket_state::closing;
  }

  if (m_uv_tcp) {

    uv_os_fd_t fd;
    if (no_linger && (uv_fileno((uv_handle_t*)m_uv_tcp, &fd) == 0)) {
      struct linger so_linger;
      so_linger.l_onoff = 1;
      so_linger.l_linger = 0;
      setsockopt(fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof so_linger);
    }

    uv_close((uv_handle_t*)m_uv_tcp, [](uv_handle_t* h) {
      /* IO thread, invoked upon uv_close completion */
      uv_handle_data* ptr = (uv_handle_data*)h->data;
      ptr->tcp_socket_ptr()->close_impl();
    });
  } else
    close_impl();
}


void tcp_socket::close_impl()
{
  decltype(m_user_close_fn) user_close_fn;
  decltype(m_io_closed_promise) closed_promise;

  /* Once the state is set to closed, this tcp_socket object may be immediately
   * deleted by another thread. So this must be the last action that makes use
   * of the tcp_socket members. */
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    m_state = socket_state::closed;

    /* Extract from the tcp_socket the child objects that need to have their
     * lifetime extended beyond that of the parent tcp_socket, so that after
     * setting of socket state to e_closed, these objects can still be
     * used. It is also important that the user-close-fn is copied inside
     * this critical section, and not before the lock is taken.*/
    user_close_fn = std::move(m_user_close_fn);
    closed_promise = std::move(m_io_closed_promise);
  }

  /* Run the user callback first, and then set the promise (the promise is set
   * as the last action, so that an owner of tcp_socket can wait on a future to
   * know when all callbacks are complete). This user callback must not perform
   * a wait on the future, because that only gets set after the callback
   * returns. */
  if (user_close_fn)
    try {
      user_close_fn();
    } catch (...) {
    }
  closed_promise->set_value();
}

std::pair<bool, int> tcp_socket::fd() const
{
  uv_os_fd_t fd;
  if (uv_fileno((uv_handle_t*)m_uv_tcp, &fd) == 0)
    return {true, fd};
  else
    return {false, -1};
}


/** User request to close socket */
std::shared_future<void> tcp_socket::close()
{
  std::lock_guard<std::mutex> guard(m_state_lock);

  if (m_state != socket_state::closing && m_state != socket_state::closed) {
    m_state = socket_state::closing;
    m_kernel->get_io()->push_fn([this]() { this->do_close(); }); // can throw
  }

  return m_io_closed_future;
}


/** User request to reset & close a socket */
std::shared_future<void> tcp_socket::reset()
{
  std::lock_guard<std::mutex> guard(m_state_lock);

  if (m_state != socket_state::closing && m_state != socket_state::closed) {
    m_state = socket_state::closing;
    m_kernel->get_io()->push_fn(
        [this]() { this->do_close(true); }); // can throw
  }

  return m_io_closed_future;
}


bool tcp_socket::close(on_close_cb user_on_close_fn)
{
  /* Note that it is safe for this to be called when state is e_closing.  In
   * such a situation the on-close callback is due to be invoked very soon (on
   * the IO thread), but because we hold the lock here, the callback function
   * can be altered before it gets invoked (see the uv_close callback).
   */

  std::lock_guard<std::mutex> guard(m_state_lock);

  // if tcp_socket is already closed, it will not be possible to later invoke
  // the user provided on-close callback, so return false
  if (m_state == socket_state::closed)
    return false;

  m_user_close_fn = user_on_close_fn;

  if (m_state != socket_state::closing) {
    m_state = socket_state::closing;
    m_kernel->get_io()->push_fn([this]() { this->do_close(); }); // can throw
  }

  return true;
}


std::future<uverr> tcp_socket::start_read(io_on_read on_read,
                                          io_on_error on_error)
{
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if (m_state != socket_state::connected)
      throw tcp_socket::error("tcp_socket: start_read() when not connected");
  }

  auto completion_promise = std::make_shared<std::promise<uverr>>();

  auto fn = [this, completion_promise]() {
    uverr ec =
        uv_read_start((uv_stream_t*)this->m_uv_tcp, iohandle_alloc_buffer,
                      [](uv_stream_t* uvh, ssize_t nread, const uv_buf_t* buf) {
          uv_handle_data* ptr = (uv_handle_data*)uvh->data;
          ptr->tcp_socket_ptr()->on_read_cb(nread, buf);
        });
    completion_promise->set_value(ec);
  };

  m_io_on_read = std::move(on_read);
  m_io_on_error = std::move(on_error);

  m_kernel->get_io()->push_fn(std::move(fn));

  return completion_promise->get_future();
}


void tcp_socket::reset_listener()
{
  m_io_on_read = nullptr;
  m_io_on_error = nullptr;
}


/* Push a close event, but unlike the user facing function 'close', does not
 * throw an exception if already has been requested to close.
 */
void tcp_socket::close_once_on_io()
{
  /* IO thread */

  std::lock_guard<std::mutex> guard(m_state_lock);
  if (m_state != socket_state::closing && m_state != socket_state::closed) {
    m_state = socket_state::closing;
    m_kernel->get_io()->push_fn([this]() { this->do_close(); });
  }
}


void tcp_socket::on_read_cb(ssize_t nread, const uv_buf_t* buf)
{
  /* IO thread */
  if (nread > 0)
    m_bytes_read += nread;

  try {
    if (nread >= 0 && m_io_on_read)
      m_io_on_read(buf->base, nread);
    else if (nread < 0 && m_io_on_error)
      m_io_on_error(uverr(nread));
  } catch (...) {
    log_exception(__logger, "IO thread in on_read_cb");
  }

  delete[] buf -> base;
}


void tcp_socket::write(std::pair<const char*, size_t>* srcbuf, size_t count)
{
  // improve memory usage here
  std::vector<uv_buf_t> bufs;

  scope_guard buf_guard([&bufs]() {
    for (auto& i : bufs)
      delete[] i.base;
  });

  bufs.reserve(count);
  for (size_t i = 0; i < count; i++) {
    uv_buf_t buf = uv_buf_init(new char[srcbuf->second], srcbuf->second);
    memcpy(buf.base, srcbuf->first, srcbuf->second);
    srcbuf++;
    bufs.push_back(buf);
  }

  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if (m_state == socket_state::closing || m_state == socket_state::closed)
      throw tcp_socket::error("tcp_socket: write() when closing or closed");

    {
      std::lock_guard<std::mutex> guard(m_pending_write_lock);
      m_pending_write.insert(m_pending_write.end(), bufs.begin(), bufs.end());
      bufs.clear();
      buf_guard.dismiss();
    }

    m_kernel->get_io()->push_fn([this]() { this->do_write(); });
  }
}


void tcp_socket::do_write()
{
  /* IO thread */

  std::vector<uv_buf_t> copy;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap(copy);
  }

  size_t bytes_to_send = 0;
  for (size_t i = 0; i < copy.size(); i++)
    bytes_to_send += copy[i].len;

  const size_t pend_max = m_kernel->get_config().socket_max_pending_write_bytes;

  if (is_connected() && !copy.empty()) {
    if (bytes_to_send > (pend_max - m_bytes_pending_write)) {
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

    int r = uv_write((uv_write_t*)wr, (uv_stream_t*)m_uv_tcp, wr->bufs,
                     wr->nbufs, [](uv_write_t* req, int status) {
      tcp_socket* the_tcp_socket = (tcp_socket*)req->data;
      the_tcp_socket->on_write_cb(req, status);
    });

    if (r) {
      LOG_WARN("uv_write failed, errno " << std::abs(r) << " ("
                                         << uv_strerror(r)
                                         << "); closing connection");
      delete wr;
      close_once_on_io();
      return;
    };
  }
}


void tcp_socket::on_write_cb(uv_write_t* req, int status)
{
  /* IO thread */

  std::unique_ptr<write_req> wr((write_req*)req); // ensure deletion

  try {
    if (status == 0) {
      size_t total = 0;
      for (size_t i = 0; i < req->nbufs; i++)
        total += req->bufsml[i].len;

      m_bytes_written += total;
      if (m_bytes_pending_write > total)
        m_bytes_pending_write -= total;
      else
        m_bytes_pending_write = 0;
    } else {
      /* write failed - this can happen if we actively terminated the socket
         while there were still a long queue of bytes awaiting output (eg inthe
         case of a slow consumer) */
      close_once_on_io();
    }
  } catch (...) {
    log_exception(__logger, "IO thread in on_write_cb");
  }
}


/**
 * Called on the IO thread when a new socket is available to be accepted.
 */
void tcp_socket::on_listen_cb(int status)
{
  /* IO thread */

  uverr ec{status};

  if (ec) {
    if (m_user_accept_fn) {
      std::unique_ptr<tcp_socket> no_socket;
      m_user_accept_fn(this, no_socket, ec);
    }
    return;
  }

  uv_tcp_t* client = new uv_tcp_t();
  uv_tcp_init(m_kernel->get_io()->uv_loop(), client);

  ec = uv_accept((uv_stream_t*)m_uv_tcp, (uv_stream_t*)client);
  if (ec == 0) {
    std::unique_ptr<tcp_socket> new_sock(
        new tcp_socket(m_kernel, client, socket_state::connected));

    if (m_user_accept_fn)
      m_user_accept_fn(this, new_sock, ec);

    if (new_sock) // user callback did not take ownership of socket
    {
      tcp_socket* ptr = new_sock.release();
      ptr->close([ptr]() { delete ptr; });
    }
  } else {
    uv_close((uv_handle_t*)client, [](uv_handle_t* h) { delete h; });
  }
}


bool tcp_socket::is_initialised() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state != socket_state::uninitialised;
}


std::future<uverr> tcp_socket::listen(const std::string& node,
                                      const std::string& service,
                                      on_accept_cb accept_fn, addr_family af)
{
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if (m_state != socket_state::uninitialised)
      throw tcp_socket::error("listen(): tcp_socket already initialised");
  }

  m_user_accept_fn = std::move(accept_fn);

  auto completion_promise = std::make_shared<std::promise<uverr>>();

  m_kernel->get_io()->push_fn([this, node, service, af, completion_promise]() {
    this->do_listen(node, service, af, completion_promise);
  });

  return completion_promise->get_future();
}


void tcp_socket::do_listen(const std::string& node, const std::string& service,
                           addr_family af,
                           std::shared_ptr<std::promise<uverr>> completion)
{
/* IO thread */

#ifndef NDEBUG
  assert(m_uv_tcp == nullptr);
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    assert(m_state == socket_state::uninitialised);
  }
#endif

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));

  switch (af) {
    case addr_family::unspec:
      hints.ai_family = AF_UNSPEC;
      break;
    case addr_family::inet4:
      hints.ai_family = AF_INET;
      break;
    case addr_family::inet6:
      hints.ai_family = AF_INET6;
      break;
  }

  hints.ai_socktype = SOCK_STREAM; /* Connection based socket */
  hints.ai_flags = AI_PASSIVE;     /* Allow wildcard IP address */

  /* getaddrinfo() returns a list of address structures than can be used in
   * later calls to bind or connect */
  uv_getaddrinfo_t req;
  uverr ec = uv_getaddrinfo(
      m_kernel->get_io()->uv_loop(), &req, nullptr /* no callback */,
      node.empty() ? nullptr : node.c_str(),
      service.empty() ? nullptr : service.c_str(), &hints);

  if (ec) {
    completion->set_value(ec);
    return;
  }

  /* Try each address until we successfullly bind. On any error we close the
   * socket and try the next address. */
  uv_tcp_t* h = nullptr;
  struct addrinfo* ai = nullptr;
  for (ai = req.addrinfo; ai != nullptr; ai = ai->ai_next) {

    h = new uv_tcp_t;
    if (uv_tcp_init(m_kernel->get_io()->uv_loop(), h) != 0) {
      delete h;
      continue;
    }

    if (uv_tcp_bind(h, ai->ai_addr, 0 /* flags */) == 0)
      break; /* success */

    uv_close((uv_handle_t*)h, [](uv_handle_t* h) { delete h; });
  }

  uv_freeaddrinfo(req.addrinfo);

  if (ai == nullptr) {
    /* no address worked, report an approporiate error code */
    completion->set_value(UV_EADDRNOTAVAIL);
    return;
  }

  m_uv_tcp = h;
  m_uv_tcp->data = new uv_handle_data(this);

  ec = uv_listen((uv_stream_t*)h, 128, [](uv_stream_t* server, int status) {
    uv_handle_data* uvhd_ptr = (uv_handle_data*)server->data;
    uvhd_ptr->tcp_socket_ptr()->on_listen_cb(status);
  });

  if (ec) {
    delete (uv_handle_data*)m_uv_tcp->data;
    m_uv_tcp = nullptr;
    uv_close((uv_handle_t*)h, [](uv_handle_t* h) { delete h; });
  } else {
    std::lock_guard<std::mutex> guard(m_state_lock);
    m_state = socket_state::listening;
  }

  completion->set_value(ec);
}


std::future<uverr> tcp_socket::connect(const std::string& node,
                                       const std::string& service,
                                       addr_family af, bool resolve_addr)
{
  {
    std::lock_guard<std::mutex> guard(m_state_lock);

    if (m_state != socket_state::uninitialised)
      throw tcp_socket::error("connect(): tcp_socket already initialised");

    m_state = socket_state::connecting;
  }

  auto completion_promise = std::make_shared<std::promise<uverr>>();

  m_kernel->get_io()->push_fn(
      [this, node, service, af, resolve_addr, completion_promise]() {
        //    this->do_listen(node, service, af, completion_promise);
      });

  return completion_promise->get_future();
}


void tcp_socket::do_connect(const std::string& node, const std::string& service,
                            addr_family af, bool resolve_addr,
                            std::shared_ptr<std::promise<uverr>> completion)
{
  /* IO thread */

  assert(m_uv_tcp == nullptr);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));

  switch (af) {
    case addr_family::unspec:
      hints.ai_family = AF_UNSPEC;
      break;
    case addr_family::inet4:
      hints.ai_family = AF_INET;
      break;
    case addr_family::inet6:
      hints.ai_family = AF_INET6;
      break;
  }

  completion->set_value(0);
}


} // namespace wampcc
