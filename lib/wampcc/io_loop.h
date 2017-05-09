/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_IOLOOP_H
#define WAMPCC_IOLOOP_H

#include "wampcc/utils.h"
#include "wampcc/error.h"

#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <memory>

#include <uv.h>

namespace wampcc
{

class io_loop;
class kernel;
class tcp_socket;
struct io_request;
struct logger;

/** Can be called by user to wampcc library to check the compile-time version of
 * libuv is the same as when wampcc was compiled. */
void version_check_libuv(int uv_major, int uv_minor);

class handle_data
{
public:
  enum { DATA_CHECK = 0x5555555555555555 };

  enum class handle_type { unknown = 0, tcp_socket, tcp_connect };

  handle_data(tcp_socket* ptr)
    : m_check(DATA_CHECK),
      m_type(handle_type::tcp_socket),
      m_tcp_socket_ptr(ptr)
  {
  }

  handle_data(handle_type ht)
    : m_check(DATA_CHECK), m_type(ht), m_tcp_socket_ptr(nullptr)
  {
  }

  uint64_t check() const { return m_check; }
  tcp_socket* tcp_socket_ptr() { return m_tcp_socket_ptr; }
  handle_type type() const noexcept { return m_type; }

private:
  uint64_t m_check; /* retain as first member */
  handle_type m_type;
  tcp_socket* m_tcp_socket_ptr;
};

void free_socket(uv_handle_t* h);

class io_loop_closed : public std::exception
{
public:
  const char* what() const noexcept override { return "io_loop closed"; }
};


/* Encapsulate the IO services.  Currently this provides a single instance of
 * the libuv even loop and IO thread. */
class io_loop
{
public:
  io_loop(kernel&, std::function<void()> io_starting_cb = nullptr);
  ~io_loop();

  /** Perform synchronous stop of the IO loop.  On return, the IO thread will
   * have been joined. */
  void sync_stop();

  void on_async();

  void cancel_connect(uv_tcp_t*);

  /** Push a function for later invocation on the IO thread.  Throws
   * io_loop_closed if the IO loop is closing or closed.
   */
  void push_fn(std::function<void()>);

  uv_loop_t* uv_loop() { return m_uv_loop; }

  logger& get_logger() const { return __logger; }
  kernel& get_kernel() const { return m_kernel; }

  /** Test whether current thread is the IO thread */
  bool this_thread_is_io() const;

private:
  void run_loop();

  void on_tcp_connect_cb(uv_connect_t* __req, int status);

  void push_request(std::unique_ptr<io_request>);

  kernel& m_kernel;
  struct logger& __logger;
  uv_loop_t* m_uv_loop;
  std::unique_ptr<uv_async_t> m_async;

  enum state { open, closing, closed } m_pending_requests_state;
  std::vector<std::unique_ptr<io_request>> m_pending_requests;
  std::mutex m_pending_requests_lock;

  synchronized_optional<std::thread::id> m_io_thread_id;

  std::thread m_thread; // prefer as final member, avoid race condition
};

} // namespace wampcc


#endif
