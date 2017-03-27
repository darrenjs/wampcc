/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/ssl_socket.h"
#include "wampcc/kernel.h"
#include "wampcc/io_loop.h"
#include "wampcc/log_macros.h"
#include "wampcc/utils.h"
#include "wampcc/ssl.h"

#include <iostream>

#include <assert.h>

namespace wampcc
{

ssl_socket::ssl_socket(kernel* k, uv_tcp_t* h, socket_state ss)
  : tcp_socket(k, h, ss),
    m_ssl(new ssl_session(k->get_ssl(), connect_mode::passive))
{
}

ssl_socket::ssl_socket(kernel* k)
  : ssl_socket(k, nullptr, socket_state::uninitialised)
{
}

ssl_socket::~ssl_socket() {}


void ssl_socket::on_read_cb(ssize_t nread, const uv_buf_t* buf)
{
  /* IO thread */

  // TODO: place socket bytes into SSL layer
  tcp_socket::on_read_cb(nread, buf);
}


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
  if (!m_ssl_on_accept_cb)
    return {};

  std::unique_ptr<ssl_socket> up;

  if (ec != 0)
    up.reset(new ssl_socket(m_kernel, h, socket_state::connected));

  m_ssl_on_accept_cb(up, ec);

  return std::unique_ptr<tcp_socket>(std::move(up));
}

}
