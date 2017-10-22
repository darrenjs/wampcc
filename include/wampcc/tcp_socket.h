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

#include <string>
#include <future>
#include <iostream>
#include <vector>

#include <string.h>

// VC++ doesn't define ssize_t, so follow definition used by libuv
#ifdef _WIN32
  #if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
    typedef intptr_t ssize_t;
    #define _SSIZE_T_
    #define _SSIZE_T_DEFINED
  #endif
#endif

/* Types defined as part of the libuv.  We don't want to include any libuv
 * headers in a wampcc public header, so instead use declarations to our
 * dependencies. */
struct uv_buf_t;
struct uv_tcp_s;
struct uv_write_s;
typedef struct uv_tcp_s uv_tcp_t;
typedef struct uv_write_s uv_write_t;

namespace wampcc
{

class io_loop;
class socket_address;
class tcp_socket;

/** A RAII utility class to manage the lifetime of a block-scope tcp_socket
 * resource.  The guard will ensure that, at scope termination, the tcp_socket
 * is correctly disposed of, either via normal destruction at scope end, or, via
 * later destruction on the wampcc IO thread. This guard implements the
 * tcp_socket ownership rule, i.e., an unclosed socket should not be deleted on
 * the IO thread. */
class tcp_socket_guard
{
public:
  tcp_socket_guard(std::unique_ptr<tcp_socket>& __sock);
  ~tcp_socket_guard();
  std::unique_ptr<tcp_socket>& sock;
};

/**
Represent a TCP socket in both server and client mode.

A socket is created and operated in either server mode or in client mode. Using
it in server mode involves use of the listen() method; using it in client mode
involves use of connect().

The owner of a tcp_socket must take special care during its deletion.  It is
undefined behaviour to invoke the tcp_socket destructor via the internal wampcc
IO thread for an instance not in the closed state.

There are three approaches to acheive safe deletion of a tcp_socket:

1. Invoke the destructor on a thread other than the wamp IO thread. It is always
   safe to delete a tcp_socket this way, no matter what the current state of the
   instance.  The destructor will, if necessary, advance the state to closed and
   perform any wait required for closed to be reached.

2. Manually ensure the instance has reached the closed state before calling the
   destructor.  The close of a tcp_socket is initiated by calling close().  Once
   initiated the socket will transition to the closed state asynchronously.  The
   caller can wait for closed to be reached by waiting on the future returned by
   close() or closed_future(). Such a wait should not be performed on the wampcc
   IO thread, since it is the IO thread that performs the internal work required
   to advance the state to closed. The method is_closed() tells if the closed
   state has been reached.

3. Delete the socket asynchronously using a callback associated with the close
   operation.  The close(on_close_cb) method initiates close of a tcp_socket;
   once the closed state has been achieved the user callback is invoked (via the
   wampcc IO thread).  Now that the close state has been reached the instance
   can be safely deleted during the callback.

In addition to these strategies a tcp_socket_guard can be used to ensure the
correct disposal of a tcp_socket that has a scoped lifetime. The guard will
detect if an unclosed tcp_socket is about to be deleted on the wampcc IO thread,
and in such situations will intervene to delete the instance via asynchronous
callback.

Using a tcp_socket_guard with a scoped tcp_socket prevents accidental unsafe
deletion.  Unintended deletion typically occurs when an exception is thrown that
leads to scope exit, and with it the deletion of associated local objects.
*/
class tcp_socket
{
public:
  enum class addr_family {
    unspec,
    inet4,
    inet6,
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
  typedef std::function<void(std::unique_ptr<tcp_socket>&,uverr)> on_accept_cb;

  tcp_socket(kernel* k);
  virtual ~tcp_socket();

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
  virtual std::future<uverr> start_read(io_on_read, io_on_error);

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
  void write(const char*, size_t);

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

  /** Obtain future that is set only when this tcp_socket is closed for future
   * callback events.*/
  std::shared_future<void> closed_future() const { return m_io_closed_future; }

  bool is_connected() const;
  bool is_connect_failed() const;
  bool is_listening() const;
  bool is_closing() const;

  /** Return whether the instance has reached the closed state. */
  bool is_closed() const;

  /** Return whether this tcp_socket has been initialised, which means it is
   * associated with an underlying socket file descriptor (until closed). */
  bool is_initialised() const;

  /** Return description of the underlying file description, if one is currently
   * associated with this tcp_socket. The first member of the pair indicates if
   * the fd is available. */
  std::pair<bool, std::string> fd_info() const;

  size_t bytes_read() const { return m_bytes_read; }
  size_t bytes_written() const { return m_bytes_written; }

  /** Return the node name, as provided during the connect / listen call. */
  const std::string& node() const;

  /** Return the service name, as provided during the connect / listen call. */
  const std::string& service() const;

  /** Return the socket local address. */
  socket_address get_local_address();

  /** Return the socket local port. */
  int get_local_port();

  /** Return the socket peer address. */
  socket_address get_peer_address();

  /** Return the socket peer port. */
  int get_peer_port();

  const kernel* get_kernel() const { return m_kernel; }
  kernel* get_kernel() { return m_kernel; }

protected:

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

  virtual void handle_read_bytes(ssize_t, const uv_buf_t*);
  virtual void service_pending_write();
  virtual tcp_socket* create(kernel*, uv_tcp_t*, socket_state);

  typedef std::function<std::unique_ptr<tcp_socket>(uverr ec,  uv_tcp_t* h)> acceptor_fn_t;
  void do_write(std::vector<uv_buf_t>&);
  std::future<uverr> listen_impl(const std::string&,const std::string&,
                                 addr_family, acceptor_fn_t);

  kernel* m_kernel;
  logger& __logger;

  /* Store of user requests to write bytes. These are queued until serviced by
   * the IO thread, via service_pending_write(). */
  std::vector<uv_buf_t> m_pending_write;
  std::mutex            m_pending_write_lock;

  /* User callbacks. */
  io_on_read m_io_on_read;
  io_on_error m_io_on_error;

  socket_state m_state;
  mutable std::mutex m_state_lock;

  mutable std::mutex m_details_lock;
  std::string m_node;
  std::string m_service;

private:
  void close_impl();

  static const char * to_string(tcp_socket::socket_state);

  void on_read_cb(ssize_t, const uv_buf_t*);
  void on_write_cb(uv_write_t*, int);
  void close_once_on_io();
  void do_write();
  void begin_close(bool no_linger = false);
  void do_listen(const std::string&, const std::string&, addr_family,
                 std::shared_ptr<std::promise<uverr>>);
  void do_connect(const std::string&, const std::string&, addr_family, bool,
                  std::shared_ptr<std::promise<uverr>>);
  void connect_completed(uverr, std::shared_ptr<std::promise<uverr>>,
                         uv_tcp_t*);
  void on_listen_cb(int);

  uv_tcp_t* m_uv_tcp;

  std::unique_ptr<std::promise<void>> m_io_closed_promise;
  std::shared_future<void> m_io_closed_future;

  std::atomic<size_t> m_bytes_pending_write;
  size_t m_bytes_written;
  size_t m_bytes_read;

  on_close_cb m_user_close_fn;

  std::shared_ptr<tcp_socket> m_self;

  /* Handler for creating a new instance when a socket is accepted. */
  acceptor_fn_t m_accept_fn;

  friend io_loop;
};

} // namespace wampcc

#endif
