/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/io_loop.h"
#include "wampcc/kernel.h"
#include "wampcc/log_macros.h"
#include "wampcc/ssl.h"
#include "wampcc/ssl_socket.h"
#include "wampcc/utils.h"

#include <assert.h>

#define DEFAULT_BUF_SIZE 4096

/* For SSL failure, represent that during the user on_error callback with a
 * suitable UV error code. */
#define SSL_UV_FAIL UV_EPROTO

namespace wampcc
{

/* Return a new uv_buf_t containg a copy of a sub-region of the source,
   starting at offset 'pos' */
static uv_buf_t sub_buf(uv_buf_t& src, size_t pos)
{
  uv_buf_t buf = uv_buf_init((char*)new char[src.len - pos], src.len - pos);
  memcpy(buf.base, src.base + pos, buf.len);
  return buf;
}


ssl_socket::ssl_socket(kernel* k, uv_tcp_t* h, socket_state ss)
  : tcp_socket(k, h, ss),
    m_ssl(new ssl_session(k->get_ssl(), connect_mode::passive)),
    m_handshake_state(t_handshake_state::pending)
{
}


ssl_socket::ssl_socket(kernel* k)
  : tcp_socket(k),
    m_ssl(new ssl_session(k->get_ssl(), connect_mode::active)),
    m_handshake_state(t_handshake_state::pending)
{
}


ssl_socket::~ssl_socket() {}


std::future<uverr> ssl_socket::listen(const std::string& node,
                                      const std::string& service,
                                      ssl_on_accept_cb user_accept_fn,
                                      addr_family af)
{
  if (is_initialised())
    throw tcp_socket::error("ssl_socket::listen() when already initialised");

  if (!user_accept_fn)
    throw tcp_socket::error("ssl_on_accept_cb is null");


  auto accept_fn=[this, user_accept_fn](uverr ec,uv_tcp_t* h) {
    std::unique_ptr<ssl_socket> up(
      h ? create(m_kernel, h, socket_state::connected) : 0);

    user_accept_fn(up, ec);

    return std::unique_ptr<tcp_socket>(std::move(up));
  };

  return listen_impl(node, service, af, std::move(accept_fn));
}


/* Service bytes waiting on the m_pending_write queue, which are due to be
 * written out of the SSL socket. These bytes must first be encrypted, and then
 * written to the underlying socket. */
void ssl_socket::service_pending_write()
{
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  // accept all unencrypted bytes that are waiting to be written
  std::vector<uv_buf_t> bufs;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    if (m_pending_write.empty())
      return;
    m_pending_write.swap(bufs);
  }

  scope_guard buf_guard([&bufs]() {
    for (auto& i : bufs)
      delete[] i.base;
  });

  for (auto it = bufs.begin(); it != bufs.end(); ++it) {
    size_t consumed = 0;
    while (consumed < it->len) {
      auto r = do_encrypt_and_write(it->base + consumed, it->len - consumed);

      if (r.first == -1) {
        m_io_on_error(uverr(SSL_UV_FAIL));
        return; /* SSL failed, so okay to discard all objects in 'bufs' */
      }

      if (r.second == 0)
        break; /* SSL_write couldn't accept data */

      consumed += r.second;
    }

    if (consumed < it->len) {
      /* SSL_write failed to fully write a buffer, but also, SSL did not report
       * an error.  Seems like some kind of flow control.  We'll keep the
       * unconsumed data, plus other pending buffers, for a later attempt. */
      std::vector<uv_buf_t> tmp{sub_buf(*it, consumed)};
      for (++it; it != bufs.end(); ++it) {
        tmp.push_back(*it);
        it->base = nullptr; /* prevent scope guard freeing the unused bytes */
      }

      std::lock_guard<std::mutex> guard(m_pending_write_lock);
      tmp.insert(tmp.end(), m_pending_write.begin(), m_pending_write.end());
      m_pending_write.swap(tmp);

      /* break loop, because iterator has been incremented in loop body,
       * otherwise the it!=end check() can be skipped over */
      break;
    }
  }
}


/* Attempt to encrypt a single block of data, by putting it through the SSL
 * object, and then take the output (representing the encrypted data) and queue
 * for socket write. Returns first==-1 on failure. */
std::pair<int, size_t> ssl_socket::do_encrypt_and_write(char* src, size_t len)
{
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  char buf[DEFAULT_BUF_SIZE];

  if (!SSL_is_init_finished(m_ssl->ssl)) {
    if (do_handshake() == sslstatus::fail)
      return {-1, 0};
    if (!SSL_is_init_finished(m_ssl->ssl))
      return {0, 0};
  }

  int w = SSL_write(m_ssl->ssl, src, len);
  if (get_sslstatus(m_ssl->ssl, w) == sslstatus::fail)
    return {-1, 0};

  /* take the output of the SSL object and queue it for socket write */
  int n;
  do {
    /* If BIO_read successfully obtained data, then n > 0.  A return value
     * of 0 or -1 does not necessarily indicate an error, in particular,
     * when used with our non-blocking memory bio. To check for an error, we
     * must use BIO_should_retry.*/

    n = BIO_read(m_ssl->wbio, buf, sizeof(buf));
    if (n > 0)
      write_encrypted_bytes(buf, n);
    else if (!BIO_should_retry(m_ssl->wbio))
      return {-1, 0};
  } while (n > 0);

  return {0, w};
}


ssl_socket::t_handshake_state ssl_socket::handshake_state()
{
  return m_handshake_state;
}


std::future<ssl_socket::t_handshake_state> ssl_socket::handshake()
{
  std::lock_guard<std::mutex> guard(m_state_lock);

  if (m_state == socket_state::uninitialised)
    throw tcp_socket::error("ssl_socket::handshake() before connect");

  if (m_state == socket_state::closing || m_state == socket_state::closed)
    throw tcp_socket::error("ssl_socket::handshake() when closing or closed");

  auto fut = m_prom_handshake.get_future();

  m_kernel->get_io()->push_fn([this]() { this->do_handshake(); });

  return fut;
}


sslstatus ssl_socket::do_handshake()
{
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  char buf[DEFAULT_BUF_SIZE];

  int n = SSL_do_handshake(m_ssl->ssl);
  sslstatus status = get_sslstatus(m_ssl->ssl, n);

  if (status == sslstatus::fail) {
    if (m_handshake_state == t_handshake_state::pending) {
      m_handshake_state = t_handshake_state::failed;
      m_prom_handshake.set_value(m_handshake_state);
    }
    return status;
  }

  /* Did SSL request to write bytes? */
  if (status == sslstatus::want_io)
    do {
      n = BIO_read(m_ssl->wbio, buf, sizeof(buf));
      if (n > 0)
        write_encrypted_bytes(buf, n);
      else if (!BIO_should_retry(m_ssl->wbio))
        return sslstatus::fail;
    } while (n > 0);

  if (SSL_is_init_finished(m_ssl->ssl) &&
      m_handshake_state == t_handshake_state::pending) {
    m_handshake_state = t_handshake_state::success;
    m_prom_handshake.set_value(m_handshake_state);
  }

  return status;
}


void ssl_socket::write_encrypted_bytes(const char* src, size_t len)
{
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  uv_buf_t buf = uv_buf_init(new char[len], len);
  memcpy(buf.base, src, len);

  std::vector<uv_buf_t> bufs{buf};
  do_write(bufs);
}


/* Arrival of raw bytes from the actual socket, if nread>0. These must be passed
 * to SSL for unencryption.  If SSL fails, or there is socket error, call the
 * user error callback.  For EOF (nread==0), invoke standard user callback.
 */
void ssl_socket::handle_read_bytes(ssize_t nread, const uv_buf_t* buf)
{
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  if (nread > 0 && ssl_do_read(buf->base, size_t(nread)) == -1)
    m_io_on_error(uverr(SSL_UV_FAIL));
  else if (nread == 0)
    m_io_on_read(nullptr, 0);
  else if (nread < 0 && m_io_on_error)
    m_io_on_error(uverr(nread));
}


/* Pass raw bytes from the socket into SSL for unencryption. */
int ssl_socket::ssl_do_read(char* src, size_t len)
{
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  char buf[DEFAULT_BUF_SIZE];

  while (len > 0) {
    int n = BIO_write(m_ssl->rbio, src, len);

    if (n <= 0)
      return -1; /* assume mem bio write error is unrecoverable */

    src += n;
    len -= n;

    /* Handle initial handshake or renegotiation */
    if (!SSL_is_init_finished(m_ssl->ssl)) {
      if (do_handshake() == sslstatus::fail)
        return -1;

      /* If we are still not initialised, then perhaps there is more data to
       * write into the read-bio? Check by continue-ing the loop. */
      if (!SSL_is_init_finished(m_ssl->ssl))
        continue;
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */
    do {
      n = SSL_read(m_ssl->ssl, buf, sizeof(buf));
      if (n > 0 && m_io_on_read)
        m_io_on_read(buf, (size_t)n);
    } while (n > 0);

    sslstatus status = get_sslstatus(m_ssl->ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (status == sslstatus::want_io)
      do {
        n = BIO_read(m_ssl->wbio, buf, sizeof(buf));
        if (n > 0)
          write_encrypted_bytes(buf, n);
        else if (!BIO_should_retry(m_ssl->wbio))
          return -1;
      } while (n > 0);

    if (status == sslstatus::fail)
      return -1;
  }

  /* In the unlikely event that there are left-over bytes from an incomplete
   * SSL_write that are waitng a retry, make attempt to serivce them. */
  service_pending_write();

  return 0;
}


/* This is the inherited virtual constructor from tcp_socket, but with a
 * ssl_socket return type (C++ covariant types). */
ssl_socket* ssl_socket::create(kernel* k, uv_tcp_t* h, tcp_socket::socket_state s)
{
  return new ssl_socket(k, h, s);
}

// namespace wampcc
}
