#ifndef XXX_PRESESSION_H
#define XXX_PRESESSION_H

#include "XXX/types.h"
#include "XXX/io_listener.h"
#include "XXX/protocol.h"

#include <jalson/jalson.h>

#include <mutex>
#include <memory>
#include <future>

namespace XXX {

  class tcp_socket;
  class kernel;
  class pre_session;
  class protocol;
  struct logger;


  class pre_session : public std::enable_shared_from_this<pre_session>,
                      public io_listener
  {
  public:

    typedef std::function< void( std::weak_ptr<pre_session> ) > on_closed_fn;
    typedef std::function< void ( protocol_builder_fn, std::unique_ptr<tcp_socket> ) > on_protocol_fn;

    // pre_session can only be created as shared_ptr
    static std::shared_ptr<pre_session> create(kernel*,
                                               std::unique_ptr<tcp_socket>,
                                               on_closed_fn state_cb,
                                               on_protocol_fn protocol_cb);
    ~pre_session();

    /** Request asynchronous close of the session */
    std::shared_future<void> close();

    std::weak_ptr<pre_session> handle() { return shared_from_this(); }

    bool is_open() const;
    bool is_pending_open() const;

    /* Number of seconds since session constructed  */
    int duration_since_creation() const;

    t_sid unique_id() const { return m_sid; }

  private:

    pre_session(kernel*,
                std::unique_ptr<tcp_socket>,
                on_closed_fn   __on_closed,
                on_protocol_fn __on_protocol);

    pre_session(const pre_session&) = delete;
    pre_session& operator=(const pre_session&) = delete;

    void io_on_close() override;
    void io_on_read(char*, size_t) override;
    void io_on_read_impl(char*, size_t);

    enum SessionState
    {
      eInit = 0,
      eClosing,
      eClosed,
      eTransferedIO
    } m_state;

    void change_state(SessionState expected, SessionState next);

    kernel * m_kernel;
    logger & __logger; /* name chosen for log macros */

    uint64_t m_sid;
    buffer   m_buf;
    std::unique_ptr<tcp_socket> m_socket;

    std::promise<void> m_has_closed;
    std::shared_future<void> m_shfut_has_closed;

    time_t m_time_create;

    on_closed_fn    m_notify_closed_cb;
    on_protocol_fn  m_protocol_cb;

    std::weak_ptr<pre_session> m_self_weak;

    friend class tcp_socket;
  };

} // namespace XXX

#endif
