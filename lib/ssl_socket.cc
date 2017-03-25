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

ssl_socket::~ssl_socket()
{
}

std::unique_ptr<tcp_socket> ssl_socket::create(uv_tcp_t* h, socket_state ss)
{
  return std::unique_ptr<tcp_socket>(new ssl_socket(m_kernel, h, ss));
}

void ssl_socket::on_read_cb(ssize_t nread, const uv_buf_t* buf)
{
  /* IO thread */

  // TODO: place socket bytes into SSL layer
  tcp_socket::on_read_cb(nread, buf);
}

}
