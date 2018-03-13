/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_KERNEL_H
#define WAMPCC_KERNEL_H

#include "wampcc/version.h"

#include <memory>
#include <string>
#include <mutex>
#include <functional>

namespace wampcc
{

class io_loop;
class event_loop;
class uri_regex;
class ssl_context;

/* Run-time name & version */
const char* package_name();    // 'wampcc'
const char* package_version(); // version, major.minor.patch
const char* package_string();  // concat of name & version
int major_version();
int minor_version();
int micro_version();

/* Logging object. Provides two functionals, wants_level() and write(), which
 * the API uses for its logging requirements.
 */
struct logger
{
  enum Level {
    eError = 0x02,
    eWarn = 0x04,
    eInfo = 0x10,
    eTrace = 0x20,
    eDebug = 0x40,
  };

  // generate bit masks to represent levels that shall be logged
  static int levels_all() { return -1; }
  static int levels_none() { return 0; }
  static int levels_upto(Level l);

  std::function<bool(Level)> wants_level;

  std::function<void(Level, const std::string&, const char* file, int ln)>
      write;

  /** Encapsulate an output stream object with a lockable behaviour.  An object
   * derived from lockable_stream can be passed to the stream() method to return
   * a logger. */
  struct lockable_stream {
    virtual std::ostream& stream() = 0;
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual ~lockable_stream(){};
  };

  /** Provide a lockable_stream object based on std::cout and a mutex. The mutex
   * is used to synchronize writes to the std::cout. */
  struct lockable_console : lockable_stream {
    static std::mutex stream_mutex;
    std::ostream& stream() override;
    void lock() override { stream_mutex.lock(); }
    void unlock() override{ stream_mutex.unlock(); }
  };

  /** Static instance of lockable_console */
  static lockable_console lockable_cout;

  /** Create a logger that writes its output to a stream using a reference to a
   * lockable_stream object.  Writing to the stream needs to be synchronised, so
   * a synchronization mechanism must also be provided. This is done by using
   * the lockable_stream interface, rather than taking an ostream& directly.  */
  static logger stream(lockable_stream&, int level_mask, bool inc_file_line = false);

  /** Return a logger object that uses std::cout.  This uses the static instance
   * lockable_cout, which provides the mutex that is used to synchronize writes
   * to std::cout. */
  static logger console(bool include_file_line = false)
  {
    return stream(lockable_cout, levels_upto(eInfo), include_file_line);
  }

  /** create a logger that does not log anything */
  static logger nolog();
};

struct ssl_config
{
  /* Must be set to true to indicate SSL should be set up. */
  bool enable;

  /* For SSL in server mode, both certificate and private key files must be
   * provided. */
  std::string certificate_file;
  std::string private_key_file;

  /* Optional custom SSL context creator (advanced usage). If this function is
   * not empty, it will be called and can return a pointer to an SSL_CTX
   * instance, which is then used internally by the wampcc kernel. Ownership of
   * any returned SSL_CTX* remains with the caller. The returned void* pointer
   * will be internally cast to an SSL_CTX* pointer. */
  std::function< void* (const struct ssl_config &)> custom_ctx_creator;

  ssl_config(bool use_ssl_) : enable(use_ssl_) {}
};

struct config
{
  size_t socket_max_pending_write_bytes;

  /** User function which gets invoked on the callback thread as soon as it
   * begins. */
  std::function<void()> event_loop_start_fn;

  /** User function which gets invoked on the callback thread just before the
   * thread completes. */
  std::function<void()> event_loop_end_fn;

  ssl_config ssl;

  config();
};

/* Core runtime.  Provides the IO layer, event thread, logging and some
 * utilities.
 */
class kernel
{
public:
  kernel(config = {}, logger nlog = logger::nolog());
  ~kernel();

  kernel(const kernel&) = delete;
  kernel& operator=(const kernel&) = delete;

  logger& get_logger() { return __logger; }
  io_loop* get_io();
  event_loop* get_event_loop();

  /* SSL context associated with the kernel. Will only be present if ssl config
   * was provided during kernel creation. */
  ssl_context* get_ssl();

  const config& get_config() const { return m_config; }

private:
  config m_config;
  logger __logger; /* name chosen for log macros */
  std::unique_ptr<io_loop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
  std::unique_ptr<ssl_context> m_ssl;
};


} // namespace wampcc

#endif
