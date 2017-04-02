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

const char * tcp_socket::to_string(socket_state s)
 {
   switch (s)
   {
     case socket_state::uninitialised : return "uninitialised";
     case socket_state::connecting : return "connecting";
     case socket_state::connected: return "connected";
     case socket_state::connect_failed: return "connect_failed";
     case socket_state::listening: return "listening";
     case socket_state::closing: return "closing";
     case socket_state::closed: return "closed";
   }
   return "unknown";
 }

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
    m_state(ss),
    m_uv_tcp(h),
    m_io_closed_promise(new std::promise<void>),
    m_io_closed_future(m_io_closed_promise->get_future()),
    m_bytes_pending_write(0),
    m_bytes_written(0),
    m_bytes_read(0),
    m_self (this, [](tcp_socket*){/* null deleter */})
{
  if (m_uv_tcp) {
    assert(m_uv_tcp->data == nullptr);
    m_uv_tcp->data = new handle_data(this);
  }
}


tcp_socket::tcp_socket(kernel* k)
  : tcp_socket(k, nullptr, socket_state::uninitialised)
{
}


tcp_socket::~tcp_socket()
{
  bool io_loop_ended = false;

  {
    /* Optionally initiate close */
    std::lock_guard<std::mutex> guard(m_state_lock);
    if ((m_state != socket_state::closing) &&
        (m_state != socket_state::closed)) {

      m_state = socket_state::closing;

      try {
        m_kernel->get_io()->push_fn([this]() { this->begin_close(); });
      } catch (io_loop_closed& e) {
        io_loop_ended = true;
      }
    }
  }

  if (!is_closed())
  {
    /* detect & caution undefined behaviour */
    if (io_loop_ended) {
      LOG_ERROR("undefined behaviour calling ~tcp_socket when IO loop closed");
    }
    else if (m_kernel->get_io() == nullptr) {
      LOG_ERROR("undefined behaviour calling ~tcp_socket when IO loop deleted");
    }
    else if (m_kernel->get_io()->this_thread_is_io()) {
      LOG_ERROR("undefined behaviour calling ~tcp_socket on IO thread");
    }
    else
      m_io_closed_future.wait();
  }

  if (m_uv_tcp) {
    delete (handle_data*)m_uv_tcp->data;;
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


bool tcp_socket::is_connect_failed() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == socket_state::connect_failed;
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
  return connect(addr, std::to_string(port), addr_family::inet4, true);
}


void tcp_socket::begin_close(bool no_linger)
{
  /* IO thread */

  // this method should only ever be called once by the IO thread, either
  // triggered by pushing a close request or a call from uv_walk.
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    m_state = socket_state::closing;
  }

  // decouple from IO request that might still be pending on the IO thread
  m_self.reset();

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
      handle_data* ptr = (handle_data*)h->data;
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
    m_kernel->get_io()->push_fn([this]() { this->begin_close(); }); // can throw
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
        [this]() { this->begin_close(true); }); // can throw
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
    m_kernel->get_io()->push_fn([this]() { this->begin_close(); }); // can throw
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
          handle_data* ptr = (handle_data*)uvh->data;
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
    m_kernel->get_io()->push_fn([this]() { this->begin_close(); });
  }
}

void tcp_socket::handle_read_bytes(ssize_t nread, const uv_buf_t* buf)
{
  if (nread >= 0 && m_io_on_read)
    m_io_on_read(buf->base, nread);
  else if (nread < 0 && m_io_on_error)
    m_io_on_error(uverr(nread));
}

void tcp_socket::on_read_cb(ssize_t nread, const uv_buf_t* buf)
{
  /* IO thread */
  if (nread > 0)
    m_bytes_read += nread;

  try {
    handle_read_bytes(nread, buf);
  }
  catch (...) {
    log_exception(__logger, "IO thread in on_read_cb");
  }

  delete[] buf -> base;
}


void tcp_socket::write(const char* src, size_t len)
{
  uv_buf_t buf;

  scope_guard buf_guard([&buf]() {
      delete[] buf.base;
    });

  buf = uv_buf_init(new char[len], len);
  memcpy(buf.base, src, len);

  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if (m_state == socket_state::closing || m_state == socket_state::closed)
      throw tcp_socket::error("tcp_socket: write() when closing or closed");

    {
      std::lock_guard<std::mutex> guard(m_pending_write_lock);
      m_pending_write.push_back(buf);
      buf_guard.dismiss();
    }

    m_kernel->get_io()->push_fn([this]() { service_pending_write(); });
  }
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

    m_kernel->get_io()->push_fn([this]() {service_pending_write();});
  }
}


void tcp_socket::do_write(std::vector<uv_buf_t>& bufs)
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  size_t bytes_to_send = 0;
  for (size_t i = 0; i < bufs.size(); i++)
    bytes_to_send += bufs[i].len;

  const size_t pend_max = m_kernel->get_config().socket_max_pending_write_bytes;

  if (is_connected() && !bufs.empty()) {
    if (bytes_to_send > (pend_max - m_bytes_pending_write)) {
      LOG_WARN("pending bytes limit reached; closing connection");
      close_once_on_io();
      return;
    }

    // build the request
    write_req* wr = new write_req(bufs.size());
    wr->req.data = this;
    for (size_t i = 0; i < bufs.size(); i++)
      wr->bufs[i] = bufs[i];

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

void tcp_socket::do_write()
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

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


std::unique_ptr<tcp_socket> tcp_socket::invoke_user_accept(uverr ec,
                                                           uv_tcp_t* h)
{
  /* IO thread */
  std::unique_ptr<tcp_socket> up(
    h? new tcp_socket(m_kernel, h, socket_state::connected):0);

  if (m_user_accept_fn)
    m_user_accept_fn(up, ec);

  return up;
}

/**
 * Called on the IO thread when a new socket is available to be accepted.
 */
void tcp_socket::on_listen_cb(int status)
{
  /* IO thread */
  uverr ec{status};

  if (ec) {
    invoke_user_accept(ec, nullptr);
    return;
  }

  uv_tcp_t* client = new uv_tcp_t();
  assert(client->data == 0);
  uv_tcp_init(m_kernel->get_io()->uv_loop(), client);

  ec = uv_accept((uv_stream_t*)m_uv_tcp, (uv_stream_t*)client);
  if (ec == 0) {
    auto new_sock = invoke_user_accept(0, client);
    if (new_sock) // user callback did not take ownership of socket
    {
      tcp_socket* ptr = new_sock.release();
      ptr->close([ptr]() { delete ptr; });
    }
  } else {
    uv_close((uv_handle_t*)client, free_socket);
  }
}


bool tcp_socket::is_initialised() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state != socket_state::uninitialised;
}


std::future<uverr> tcp_socket::listen_impl(const std::string& node,
                                           const std::string& service,
                                           addr_family af)
{
  auto completion_promise = std::make_shared<std::promise<uverr>>();

  m_kernel->get_io()->push_fn([this, node, service, af, completion_promise]() {
    this->do_listen(node, service, af, completion_promise);
  });

  return completion_promise->get_future();
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

  return listen_impl(node, service, af);
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
  hints.ai_protocol = IPPROTO_TCP;

  /* getaddrinfo() returns a list of address structures that can be used in
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

    h = new uv_tcp_t();
    assert(h->data == 0);
    if (uv_tcp_init(m_kernel->get_io()->uv_loop(), h) != 0) {
      delete h;
      continue;
    }

    if (uv_tcp_bind(h, ai->ai_addr, 0 /* flags */) == 0)
      break; /* success */

    uv_close((uv_handle_t*)h, free_socket);
  }

  uv_freeaddrinfo(req.addrinfo);

  if (ai == nullptr) {
    /* no address worked, report an approporiate error code */
    completion->set_value(UV_EADDRNOTAVAIL);
    return;
  }

  m_uv_tcp = h;
  m_uv_tcp->data = new handle_data(this);

  ec = uv_listen((uv_stream_t*)h, 128, [](uv_stream_t* server, int status) {
    handle_data* uvhd_ptr = (handle_data*)server->data;
    uvhd_ptr->tcp_socket_ptr()->on_listen_cb(status);
  });

  if (ec) {
    m_uv_tcp = nullptr;
    uv_close((uv_handle_t*)h, free_socket);
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
        this->do_connect(node, service, af, resolve_addr, completion_promise);
      });

  return completion_promise->get_future();
}


struct connect_context
{
  uv_connect_t request; // must be first, allow for casts
  std::shared_ptr<std::promise<uverr>> completion;
  std::weak_ptr<tcp_socket> wp;

  connect_context(std::shared_ptr<std::promise<uverr>> p,
                  std::weak_ptr<tcp_socket> sock)
    : completion(p), wp(std::move(sock)) { }

};


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

  hints.ai_socktype = SOCK_STREAM; /* Connection based socket */
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_socktype = resolve_addr ? 0 : (AI_NUMERICHOST | AI_NUMERICSERV);

  /* getaddrinfo() returns a list of address structures that can be used in
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

  /* Try each address until a call to connect is successful. On any error we
   * close the socket and try the next address. */
  uv_tcp_t* h = nullptr;
  struct addrinfo* ai = nullptr;
  for (ai = req.addrinfo; ai != nullptr; ai = ai->ai_next) {

    h = new uv_tcp_t();
    assert(h->data == 0);
    if (uv_tcp_init(m_kernel->get_io()->uv_loop(), h) != 0) {
      delete h;
      continue;
    }
    h->data = new handle_data(handle_data::handle_type::tcp_connect);

    auto* ctx = new connect_context(completion, m_self);

    ec = uv_tcp_connect((uv_connect_t*)ctx, h, ai->ai_addr,
                        [](uv_connect_t* req, int status) {
      std::unique_ptr<connect_context> ctx((connect_context*)req);

      if (auto sp = ctx->wp.lock())
      {
        sp->connect_completed(status, ctx->completion,
                              (uv_tcp_t*)req->handle);
      }
      else
      {
        /* We no longer have a reference to the original tcp_socket.  This
         * happens when the tcp_socket object has been deleted before the
         * uv_connect callback was called.  We have no use for the current
         * uv_tcp_t handle, so just delete.  We also check that the handle is
         * not already closing, which may be the case if the IO loop has been
         * shutdown.
         */
        if (!uv_is_closing((uv_handle_t*) req->handle))
          uv_close((uv_handle_t*) req->handle, free_socket);
      }
    });

    if (ec == 0)
      break; /* success, connect in progress */

    delete ctx;
    uv_close((uv_handle_t*)h, free_socket);
  }

  uv_freeaddrinfo(req.addrinfo);

  if (ai == nullptr) {
    /* no address worked, use the last error code seen if non-zero */
    completion->set_value(ec ? ec : UV_EADDRNOTAVAIL);
    return;
  }

  /* Note: completion is only set during the connect_completed callback */
}


void tcp_socket::connect_completed(
    uverr ec, std::shared_ptr<std::promise<uverr>> completion, uv_tcp_t* h)
{
  /* IO thread */
  std::lock_guard<std::mutex> guard(m_state_lock);

  /* State might be closed/closing, which can happen if a tcp_socket is deleted
   * before the a previous connect attempt has completed. */
  assert(m_uv_tcp == nullptr);
  assert(m_state == socket_state::connecting
         || m_state == socket_state::closing );

  if (ec == 0) {
    m_state = socket_state::connected;
    m_uv_tcp = h;
    auto ptr = (handle_data*) m_uv_tcp->data;
    *ptr = handle_data(this);
  } else {
    m_state = socket_state::connect_failed;
    uv_close((uv_handle_t*)h, free_socket);
  }

  completion->set_value(ec);
}

void tcp_socket::service_pending_write()
{
  do_write();
}

} // namespace wampcc
