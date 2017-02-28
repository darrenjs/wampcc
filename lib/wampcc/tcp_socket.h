/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_TCP_SOCKET_H
#define WAMPCC_TCP_SOCKET_H

#include "wampcc/kernel.h"
#include "wampcc/error.h"

#include <uv.h>

#include <string>
#include <future>
#include <iostream>
#include <vector>

#include <string.h>
#include <unistd.h>

namespace wampcc
{

class io_loop;

/**
 * Represent a TCP socket, in both server mode and client mode.
 */
class tcp_socket
{
public:
  enum class addr_family {
    unspec = AF_UNSPEC,
    inet4 = AF_INET,
    inet6 = AF_INET6,
  };

  /** Type thrown by tcp_socket when actions are attempted when the socket is
   * not in an appropriate state. */
  class error : public std::runtime_error
  {
  public:
    error(std::string msg) : std::runtime_error(msg) {}
  };

  typedef std::function<void(char*, size_t)> io_on_read;
  typedef std::function<void(uverr)> io_on_error;
  typedef std::function<void()> on_close_cb;
  typedef std::function<
      void(tcp_socket* server, std::unique_ptr<tcp_socket>& client, uverr)>
      on_accept_cb;

  tcp_socket(kernel* k);
  ~tcp_socket();

  tcp_socket(const tcp_socket&) = delete;
  tcp_socket& operator=(const tcp_socket&) = delete;

  /** Request TCP connection to a remote end point, using IPv4 and allowing DNS
   * resolution.  This should only be called on an uninitialised socket. */
  std::future<uverr> connect(std::string addr, int port);

  /** Request TCP connection to a remote end point.  This should only be called
   * on an uninitialised socket. */
  std::future<uverr> connect(const std::string& node,
                             const std::string& service,
                             addr_family = addr_family::unspec,
                             bool resolve_addr = true);

  /** Request socket begins reading inbound data, with callbacks make on the IO
   * thread. */
  std::future<uverr> start_read(io_on_read, io_on_error);

  /** Reset IO callbacks */
  void reset_listener();

  /** Initialise this tcp_socket by creating a listen socket that is bound to
   * the specified end point. The user callback is called when an incoming
   * connection request is accepted. Node can be the empty string, in which case
   * the listen socket will accept incoming connections from all interfaces
   * (i.e. INADDR_ANY). */
  std::future<uverr> listen(const std::string& node, const std::string& service,
                            on_accept_cb, addr_family = addr_family::unspec);

  /* Request a write */
  void write(std::pair<const char*, size_t>* srcbuf, size_t count);

  /** Request asynchronous socket close. To detect when close has occured, the
   * caller can wait upon the returned future.  Throws io_loop_closed if IO loop
   * has already been closed. */
  std::shared_future<void> close();

  /** Request asynchronous socket reset & close.  */
  std::shared_future<void> reset();

  /** Request asynchronous socket close, and recieve notification via the
   * specified callback on the IO thread. If the tcp_socket is not currently
   * closed then the provided callback is invoked at the time of socket closure
   * and true is returned.  Otherwise, if the socket is already closed, the
   * callback is never invoked and false is returned. Throws io_loop_closed if
   * IO loop has already been closed. */
  bool close(on_close_cb);

  bool is_connected() const;
  bool is_connect_failed() const;
  bool is_listening() const;
  bool is_closing() const;
  bool is_closed() const;

  /** Return whether this tcp_socket has been initialised, which means it is
   * associated with an underlying socket file descriptor (until closed). */
  bool is_initialised() const;

  /** Return the underlying file description, if one is currently associated
   * with this tcp_socket. */
  std::pair<bool, int> fd() const;

  size_t bytes_read() const { return m_bytes_read; }
  size_t bytes_written() const { return m_bytes_written; }

  std::shared_future<void> closed_future() const { return m_io_closed_future; }

private:
  enum class socket_state {
    uninitialised,
    connecting,
    connected,
    connect_failed,
    listening,
    closing,
    closed
  };

  tcp_socket(kernel* k, uv_tcp_t*, socket_state ss);
  void on_read_cb(ssize_t, const uv_buf_t*);
  void on_write_cb(uv_write_t*, int);
  void close_once_on_io();
  void do_write();
  void do_close(bool no_linger = false);
  void do_listen(const std::string&, const std::string&, addr_family,
                 std::shared_ptr<std::promise<uverr>>);
  void do_connect(const std::string&, const std::string&, addr_family, bool,
                  std::shared_ptr<std::promise<uverr>>);
  void connect_completed(uverr, std::shared_ptr<std::promise<uverr>>,
                         uv_tcp_t*);
  void on_listen_cb(int);
  void close_impl();
  kernel* m_kernel;
  logger& __logger;

  uv_tcp_t* m_uv_tcp;

  socket_state m_state;
  mutable std::mutex m_state_lock;

  std::unique_ptr<std::promise<void>> m_io_closed_promise;
  std::shared_future<void> m_io_closed_future;

  std::atomic<size_t> m_bytes_pending_write;
  size_t m_bytes_written;
  size_t m_bytes_read;

  io_on_read m_io_on_read;
  io_on_error m_io_on_error;

  std::vector<uv_buf_t> m_pending_write;
  std::mutex m_pending_write_lock;

  on_accept_cb m_user_accept_fn;
  on_close_cb m_user_close_fn;

  friend io_loop;
};

} // namespace wampcc

#endif
