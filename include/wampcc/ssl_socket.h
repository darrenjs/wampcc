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
enum class sslstatus;

/**
 * Represent an SSL TCP socket, in both server mode and client mode. Instances
 * of this class can only be created if the wampcc kernel has an SSL context.
 */
class ssl_socket : public tcp_socket
{
public:
  enum class t_handshake_state { pending, success, failed };

  typedef std::function<void(std::unique_ptr<ssl_socket>&, uverr)>
      ssl_on_accept_cb;

  ssl_socket(kernel* k);
  ~ssl_socket();
  ssl_socket(const ssl_socket&) = delete;
  ssl_socket& operator=(const ssl_socket&) = delete;

  /* Request the asynchronous send of the SSL client handshake.  This can be
   * called after connect() has successfully completed.  Note that this does not
   * have to be called. Any attempt to write data to a SSL connection which has
   * not completed the handshake will cause a handshake attempt to be
   * automatically made. Should not be called more than once. */
  std::future<t_handshake_state> handshake();

  /* Has the initial SSL handshake been completed? */
  t_handshake_state handshake_state();

  /** Initialise this ssl_socket by creating a listen socket that is bound to
   * the specified end point. The user callback is called when an incoming
   * connection request is accepted. Node can be the empty string, in which case
   * the listen socket will accept incoming connections from all interfaces
   * (i.e. INADDR_ANY). */
  std::future<uverr> listen(const std::string& node, const std::string& service,
                            ssl_on_accept_cb,
                            addr_family = addr_family::unspec);

private:
  ssl_socket(kernel* k, uv_tcp_t*, socket_state ss);

  void handle_read_bytes(ssize_t, const uv_buf_t*) override;
  void service_pending_write() override;
  ssl_socket* create(kernel*, uv_tcp_t*, tcp_socket::socket_state) override;

  std::pair<int, size_t> do_encrypt_and_write(char*, size_t);
  sslstatus do_handshake();
  void write_encrypted_bytes(const char* src, size_t len);
  int ssl_do_read(char* src, size_t len);

  std::unique_ptr<ssl_session> m_ssl;

  t_handshake_state m_handshake_state;
  std::promise<t_handshake_state> m_prom_handshake;
};
}

#endif
