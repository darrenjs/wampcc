/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_SSL_SOCKET_H
#define WAMPCC_SSL_SOCKET_H

#include "wampcc/tcp_socket.h"

namespace wampcc
{

class ssl_session;

/**
 * Represent an SSL TCP socket, in both server mode and client mode. Instances
 * of this class can only be created if the wampcc kernel has an SSL context.
 */
class ssl_socket : public tcp_socket
{
public:
  ssl_socket(kernel* k);
  ~ssl_socket();

  ssl_socket(const ssl_socket&) = delete;
  ssl_socket& operator=(const ssl_socket&) = delete;

protected:

  std::unique_ptr<tcp_socket> create(uv_tcp_t*, socket_state) override;
  void on_read_cb(ssize_t, const uv_buf_t*) override;

private:
  ssl_socket(kernel* k, uv_tcp_t*, socket_state ss);
  std::unique_ptr<ssl_session> m_ssl;
};

}

#endif
