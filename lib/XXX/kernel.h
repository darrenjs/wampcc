#ifndef XXX_KERNEL_H
#define XXX_KERNEL_H

#include <memory>
#include <mutex>
#include <functional>

namespace XXX {

class io_loop;
class event_loop;
class uri_regex;

/* Logging object. Provides two functionals, wants_level and write, which the
 * API uses for its logging requirements.
 */
struct logger
{
  enum Level {eError = 0x02,
              eWarn  = 0x04,
              eInfo  = 0x10,
              eDebug = 0x40};

  // generate bit masks to represent levels that shall be logged
  static int levels_all  () { return -1; }
  static int levels_none () { return 0; }
  static int levels_upto (Level l);

  std::function<bool(Level)> wants_level;
  std::function<void(Level, const std::string&, const char* file, int ln)> write;

  /** create a logger for stdout or stderr */
  static logger stdlog(std::ostream&, int level_mask, bool inc_file_line);

  /** create a logger for stdout that logs error,warn and info */
  static logger stdout();

  /** create a logger that does not log anything */
  static logger nolog();
};


struct config
{
  size_t socket_buffer_max_size_bytes;
  size_t socket_max_pending_write_bytes;

  /** Generate and expect WAMP session heartbeats. */
  bool   use_wamp_heartbeats = false;

  /** User function which gets invoked on the callback thread as soon as it
   * begins. */
  std::function<void()> event_loop_start_fn;

  /** User function which gets invoked on the callback thread just before the
   * thread completes. */
  std::function<void()> event_loop_end_fn;

  config()
    : socket_buffer_max_size_bytes(65536),
      socket_max_pending_write_bytes(65536)
  {
  }
};

/* Core runtime.  Provides the IO layer, event thread, logging and some
 * utilities.
 */
class kernel
{
public:
  kernel(config, logger nlog);
  ~kernel();

  kernel(const kernel&) = delete;
  kernel& operator=(const kernel&) = delete;

  logger&      get_logger() { return __logger; }
  io_loop*     get_io();
  event_loop*  get_event_loop();

  const config& get_config() const { return m_config; }

private:
  config m_config;
  logger __logger; /* name chosen for log macros */
  std::unique_ptr<io_loop> m_io_loop;
  std::unique_ptr<event_loop> m_evl;
};


} // namespace XXX

#endif
