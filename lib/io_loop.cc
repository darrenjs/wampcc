/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/io_loop.h"

#include "wampcc/log_macros.h"
#include "wampcc/kernel.h"
#include "wampcc/tcp_socket.h"
#include "wampcc/utils.h"

#include <system_error>

#include <string.h>
#include <assert.h>
#include <iostream>

namespace wampcc {

void free_socket(uv_handle_t* h)
{
  if (h) {
    delete (handle_data*) h->data;
    delete h;
  }
}

struct io_request
{
  enum class request_type
  {
    cancel_handle,
    close_loop,
    function
  } type;

  logger & logptr;
  uv_tcp_t * tcp_handle = nullptr;
  std::function<void()> user_fn;

  io_request(request_type __type,
             logger & __logger)
    : type(__type),
      logptr(__logger)
  {}
};


io_loop::io_loop(kernel& k, std::function<void()> io_started_cb)
  : m_kernel(k),
    __logger( k.get_logger() ),
    m_uv_loop( new uv_loop_t() ),
    m_async( new uv_async_t() ),
    m_pending_requests_state(state::open)
{
  version_check_libuv(UV_VERSION_MAJOR, UV_VERSION_MINOR);

  uv_loop_init(m_uv_loop);
  m_uv_loop->data = this;

  // set up the async handler
  uv_async_init(m_uv_loop, m_async.get(), [](uv_async_t* h) {
      io_loop* p = static_cast<io_loop*>( h->data );
      p->on_async();
    });
  m_async->data = this;

  // prevent SIGPIPE from crashing application when socket writes are
  // interrupted
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);  // TODO: add support for Windows
#endif

  m_thread = std::thread([this, io_started_cb]() {

      scope_guard undo_thread_id([this](){ m_io_thread_id.release(); });
      m_io_thread_id.set_value(std::this_thread::get_id());

      if (io_started_cb)
        try {
          io_started_cb();
        } catch(...){ /* ignore */}

      try {
        io_loop::run_loop();
      } catch(...){ /* ignore */}

    });
}


void io_loop::sync_stop()
{
  std::unique_ptr<io_request> r( new io_request( io_request::request_type::close_loop,
                                                 __logger) );

  try {
    push_request(std::move(r));
  }
  catch (io_loop_closed&) { /* ignore */  }

  if (m_thread.joinable())
    m_thread.join();
}


io_loop::~io_loop()
{
  uv_loop_close(m_uv_loop);
  delete m_uv_loop;
}


void io_loop::on_async()
{
  /* IO thread */
  std::vector< std::unique_ptr<io_request> > work;

  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);
    work.swap( m_pending_requests );
    if (m_pending_requests_state == state::closing)
      m_pending_requests_state = state::closed;
  }

  for (auto & user_req : work)
  {
    if (user_req->type == io_request::request_type::cancel_handle)
    {
      auto handle_to_cancel = (uv_handle_t*) user_req->tcp_handle;
      if (!uv_is_closing(handle_to_cancel))
        uv_close(handle_to_cancel, [](uv_handle_t* handle) {
            delete handle;
          });
    }
    else if (user_req->type == io_request::request_type::close_loop)
    {
      /* close event handler run at function exit */
    }
    else if (user_req->type == io_request::request_type::function)
    {
      user_req->user_fn();
    }
    else
    {
      assert(false);
    }
  }


  if (m_pending_requests_state == state::closed)
  {
    uv_close((uv_handle_t*) m_async.get(), 0);

    // While there are active handles, progress the event loop here and on
    // each iteration identify and request close any handles which have not
    // been requested to close.
    uv_walk(m_uv_loop, [](uv_handle_t* handle, void* arg) {

        if (!uv_is_closing(handle))
        {
          handle_data * ptr = (handle_data*) handle->data;

          if (ptr == 0)
          {
            // We are uv_walking a handle which does not have the data member
            // set. Common cause of this is a shutdown of the kernel & ioloop
            // while a wamp_connector exists which has not had its UV handle
            // used.
            uv_close(handle, [](uv_handle_t* h){
                delete h;
              });
          }
          else
          {
            assert(ptr->check() == handle_data::DATA_CHECK);

            if (ptr->type() == handle_data::handle_type::tcp_socket)
              ptr->tcp_socket_ptr()->begin_close();
            else if (ptr->type() == handle_data::handle_type::tcp_connect)
              uv_close(handle, free_socket);
            else
            {
              /* unknown handle, so just close it */
              assert(0);
              uv_close(handle, [](uv_handle_t* h){ delete h; });
            }
          }
        }
      }, nullptr);

  }

}


bool io_loop::this_thread_is_io() const
{
  return m_io_thread_id.compare(std::this_thread::get_id());
}


void io_loop::run_loop()
{
  while (true)
  {
    try
    {
      int r = uv_run(m_uv_loop, UV_RUN_DEFAULT);

      if (r == 0) /*  no more handles; we are shutting down */
        return;
    }
    catch(const std::exception & e)
    {
      LOG_ERROR("io_loop exception: " << e.what());
    }
    catch(...)
    {
      LOG_ERROR("uknown io_loop exception");
    }
  }
}


void io_loop::cancel_connect(uv_tcp_t * handle)
{
  std::unique_ptr<io_request> r( new io_request(io_request::request_type::cancel_handle, __logger ) );
  r->tcp_handle = handle;
  push_request(std::move(r));
}


void io_loop::push_request(std::unique_ptr<io_request> r)
{
  {
    std::lock_guard< std::mutex > guard (m_pending_requests_lock);

    if (m_pending_requests_state == state::closed)
      throw io_loop_closed();

    if (r->type == io_request::request_type::close_loop)
      m_pending_requests_state = state::closing;

    m_pending_requests.push_back( std::move(r) );
  }

  uv_async_send( m_async.get() ); // wake-up IO thread
}


void io_loop::push_fn(std::function<void()> fn)
{
  std::unique_ptr<io_request> r( new io_request( io_request::request_type::function,
                                                 __logger) );
  r->user_fn = std::move(fn);
  push_request(std::move(r));
}


void version_check_libuv(int compile_major, int compile_minor)
{
  // version that wampcc library was built with
  int library_major = UV_VERSION_MAJOR;
  int library_minor = UV_VERSION_MINOR;

  // version we are linked to at runtime
  int runtime_major = (uv_version() & 0xFF0000) >> 16;
  int runtime_minor = (uv_version() & 0x00FF00) >> 8;

  // check all versions are consistent
  if ( compile_major != library_major || compile_major != runtime_major ||
       compile_minor != library_minor || compile_minor != runtime_minor)
  {
    std::ostringstream oss;
    oss << "libuv version mismatch; "
        << "user-compile-time: " << compile_major  << "." << compile_minor
        << ", library-compile-time: " << library_major  << "." << library_minor
        << ", link-time: " << runtime_major << "." << runtime_minor;
    throw std::runtime_error( oss.str() );
  }
}


} // namespace wampcc
