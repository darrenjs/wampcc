#ifndef XXX_SESSION_H
#define XXX_SESSION_H

#include "Callbacks.h"

#include "io_listener.h"

#include <jalson/jalson.h>

#include <map>
#include <mutex>
#include <memory>

namespace XXX {


  // TODO: this can probably be moved to an impl file.
  struct Request_CB_Data
  {
    virtual ~Request_CB_Data() {}
  };


  typedef std::function< std::pair< jalson::json_array, Request_CB_Data*> (int) > build_message_cb_v2;
  typedef std::function<  jalson::json_array  ()    > build_message_cb_v4;


  class event_loop;
  class IOHandle;
  class SessionMan;


  class Logger;

  struct PendingReq;

  struct PendingReq2
  {
    unsigned int request_type;
    unsigned int external_req_id;
    unsigned int internal_req_id;
    void * user;

    PendingReq2()
      : request_type(0),
        external_req_id(0),
        internal_req_id(0),
        user(0)
    {
    }

  };

  struct Request_CB_Data;



  // Needs to support needs of service providers (rpc & topics), and service
  // consumers (rpc callers, and subscribers)
  class Session : public io_listener
  {
  public:
    Session(SID, Logger*, IOHandle *,
            event_loop&, bool is_passive,
            t_connection_id user_conn_id,
            std::string realm = "" /* should be empty for passive session */);
    ~Session();

    void send_request( int request_type,
                       unsigned int internal_req_id,
                       build_message_cb_v2 msg_builder );

    void subscribe()  {}

    bool send_bytes(std::pair<const char*, size_t>*, size_t, bool final);

    void send_msg(jalson::json_array&, bool final=false);
    void send_msg(build_message_cb_v4 builder);

    void close();

    void remove_listener();

    session_handle handle() { return m_session_handle; }

    bool is_open() const;
    bool is_pending_open() const;

    void initiate_handshake();

    /* If session is not open, then return number of milliseconds since
     * creation.  Else return 0/  */
    int duration_pending_open() const;

    /* Time since last message */
    int duration_since_last() const;

    /* return the realm, or empty string if a realm has not yet been provided,
     * eg, in case of a passive session */
    std::string realm() const;

    int hb_interval_secs() const { return m_hb_intvl; }

  private:
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void on_close() override;
    void on_read(char*, size_t) override;
    void on_read_impl(char*, size_t);
    void decode_and_process(char*, size_t len);
    void process_message(jalson::json_value&);


    void update_state_for_outbound(const jalson::json_array& msg);

    friend class IOHandle;

    enum SessionState
    {
      eInit = 0,
      eRecvHello,
      eSentChallenge,
      eRecvAuth,
      eOpen,
      eClosed,

      // next are client state values
      eSentHello,
      eRecvChallenge,
      eSentAuth,

      eStateMax
    } m_state;   // TODO: this is my experiment with makeing a session specific to a session owned by a delare

    void change_state(SessionState expected, SessionState next);

    void handle_HELLO(jalson::json_array& ja);
    void handle_CHALLENGE(jalson::json_array& ja);
    void handle_AUTHENTICATE(jalson::json_array& ja);
    void handle_ABORT(jalson::json_array& ja);
    void handle_WELCOME(jalson::json_array& ja);

    void notify_session_state_change(bool is_open);


    Logger *__logptr; /* name chosen for log macros */

    std::mutex m_handle_lock;
    IOHandle* m_handle;

    /* Interval, in secs, at which to send heartbeats. Values below 30 seconds
        might not be too reliable, because the underlying housekeeping timer has
        around a 20 second precision. */
    int m_hb_intvl;
    time_t m_time_create;

    time_t m_time_last_msg;

    t_request_id m_next_request_id;

    char *  m_buf;
    size_t  m_bytes_avail;

    bool m_is_closing;

    event_loop & m_evl;

    bool m_is_passive;

    jalson::json_value m_challenge; // full message


    std::string m_realm;
    mutable std::mutex m_realm_lock;

  private:
    // TODO: why two?
    std::map<int, PendingReq* > m_pend_req;
    std::map<int, PendingReq2 > m_pend_req_2;
    std::mutex m_pend_req_lock;

    std::shared_ptr< t_sid > m_session_handle;

    t_connection_id m_user_conn_id;

    session_error::error_code m_session_err = session_error::no_error;
  };

} // namespace XXX

#endif
