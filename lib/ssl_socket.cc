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

ssl_socket::ssl_socket(kernel* k, uv_tcp_t* h, socket_state ss)
  : tcp_socket(k, h, ss),
    m_ssl(new ssl_session(k->get_ssl(), connect_mode::passive))
{
}


ssl_socket::ssl_socket(kernel* k)
  : tcp_socket(k), m_ssl(new ssl_session(k->get_ssl(), connect_mode::active))
{
}


ssl_socket::~ssl_socket() {}


std::future<uverr> ssl_socket::listen(const std::string& node,
                                      const std::string& service,
                                      ssl_on_accept_cb accept_fn,
                                      addr_family af)
{
  if (is_initialised())
    throw tcp_socket::error("listen(): ssl_socket already initialised");

  m_ssl_on_accept_cb = std::move(accept_fn);

  return listen_impl(node, service, af);
}


std::unique_ptr<tcp_socket> ssl_socket::invoke_user_accept(uverr ec,
                                                           uv_tcp_t* h)
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  std::unique_ptr<ssl_socket> up(
      h ? new ssl_socket(m_kernel, h, socket_state::connected) : 0);

  if (m_ssl_on_accept_cb)
    m_ssl_on_accept_cb(up, ec);

  return std::unique_ptr<tcp_socket>(std::move(up));
}


void ssl_socket::service_pending_write()
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  /* To service the pending write bytes, we cannot immediately write them to the
   * socket as tcp_socket does.  Instead we must pass them through the SSL
   * object for encryption, and then write them. */
  if (do_encrypt_and_write() == -1)
    m_io_on_error(uverr(SSL_UV_FAIL));
}


/* Service bytes waiting on the m_pending_write queue, which are due to be
 * written out of the SSL socket. These bytes must first be encrypted, and then
 * written to the underlying socket. */
int ssl_socket::do_encrypt_and_write()
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  char buf[DEFAULT_BUF_SIZE];

  if (!SSL_is_init_finished(m_ssl->ssl)) {
    if (do_handshake() == sslstatus::fail)
      return -1;
    if (!SSL_is_init_finished(m_ssl->ssl))
      return 0;
  }

  // accept all unencrypted bytes that are waiting to be written
  std::vector<uv_buf_t> copy;
  {
    std::lock_guard<std::mutex> guard(m_pending_write_lock);
    m_pending_write.swap(copy);
  }

  /* TODO: need better byte handling here, e.g, maybe not all the bytes could be
   * written into the bio? */
  for (auto& src : copy) {
    int n = SSL_write(m_ssl->ssl, src.base, src.len);
    sslstatus status = get_sslstatus(m_ssl->ssl, n);

    if (n > 0) {
      /* consume the waiting bytes that have been used by SSL */

      // TODO: DJS!!! this needs to be adapted for the buffers I am using

      /* take the output of the SSL object and queue it for socket write */
      do {
        /* If BIO_read successfully obtained data, then n > 0.  A return value
         * of 0 or -1 does not necessarily indicate an error, in particular,
         * when used with our non-blocking memory bio. To check for an error, we
         * must use BIO_should_retry.*/

        n = BIO_read(m_ssl->wbio, buf, sizeof(buf));
        if (n > 0)
          write_encrypted_bytes(buf, n);
        else if (!BIO_should_retry(m_ssl->wbio))
          return -1;
      } while (n > 0);
    }
  }

  return 0;
}


sslstatus ssl_socket::do_handshake()
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  char buf[DEFAULT_BUF_SIZE];

  int n = SSL_do_handshake(m_ssl->ssl);
  sslstatus status = get_sslstatus(m_ssl->ssl, n);

  /* Did SSL request to write bytes? */
  if (status == sslstatus::want_io)
    do {
      n = BIO_read(m_ssl->wbio, buf, sizeof(buf));
      if (n > 0)
        write_encrypted_bytes(buf, n);
      else if (!BIO_should_retry(m_ssl->wbio))
        return sslstatus::fail;
    } while (n > 0);

  if (SSL_is_init_finished(m_ssl->ssl)) {
    // TODO: notify condition variable, for first handshake
  }

  return status;
}


void ssl_socket::write_encrypted_bytes(const char* src, size_t len)
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  uv_buf_t buf = uv_buf_init(new char[len], len);
  memcpy(buf.base, src, len);

  std::vector<uv_buf_t> bufs{buf};
  do_write(bufs);
}


void ssl_socket::handle_read_bytes(ssize_t nread, const uv_buf_t* buf)
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  if (nread > 0 && ssl_do_read(buf->base, size_t(nread)) == -1)
    m_io_on_error(uverr(SSL_UV_FAIL));
  else if (nread < 0 && m_io_on_error)
    m_io_on_error(uverr(nread));
}


int ssl_socket::ssl_do_read(char* src, size_t len)
{
  /* IO thread */
  assert(m_kernel->get_io()->this_thread_is_io() == true);

  char buf[DEFAULT_BUF_SIZE];

  while (len > 0) {
    int n = BIO_write(m_ssl->rbio, src, len);

    if (n <= 0)
      return -1;

    src += n;
    len -= n;

    /* Handle initial handshake or renegotiation */
    if (!SSL_is_init_finished(m_ssl->ssl)) {
      if (do_handshake() == sslstatus::fail)
        return -1;
      if (!SSL_is_init_finished(m_ssl->ssl))
        return 0;
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

  return 0;
}
}
