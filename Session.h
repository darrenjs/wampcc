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
  typedef std::function<  jalson::json_array  (int) > build_message_cb_v3;
  typedef std::function<  jalson::json_array  ()    > build_message_cb_v4;


  class event_loop;
  class IOHandle;
  class SessionListener;
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
            SessionListener*, event_loop&, bool is_dealer);
    ~Session();

    /* Build CALL and enque on socket. Currently used by client-code. Might not
     * be the best place for it? */
    void call( const std::string& procedure);

    // /* Build REGISTER and enque on socket */
    // void send_register(int, const std::string& procedure, Request_CB_Data* = 0);

    void send_request( int request_type,
                       unsigned int internal_req_id,
                       build_message_cb_v2 msg_builder );

    void send_request( int request_type,
                       build_message_cb_v3 msg_builder,
                       Request_CB_Data* = 0);

    void subscribe()  {}

    bool send_bytes(std::pair<const char*, size_t>*, size_t, bool final);

    void send_msg(jalson::json_array&, bool final=false);
    void send_msg(build_message_cb_v4 builder);

    void close(int);

    void remove_listener();

    session_handle handle() { return m_session_handle; }

    bool is_open() const;

  private:
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void on_close(int) override;
    void on_read(char*, size_t) override;
    void on_read_impl(char*, size_t);
    void process_message(jalson::json_value&);

    void update_state_for_outbound(const jalson::json_array& msg);



    friend class IOHandle;

    enum DealerState
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

    void change_state(DealerState expected, DealerState next);

    void handle_HELLO(jalson::json_array& ja);
    void handle_CHALLENGE(jalson::json_array& ja);
    void handle_AUTHENTICATE(jalson::json_array& ja);
    void handle_ABORT(jalson::json_array& ja);
    void handle_WELCOME(jalson::json_array& ja);

    void notify_session_state_change(bool is_open);


    Logger *__logptr; /* name chosen for log macros */
    SessionListener * m_listener;

    std::mutex m_handle_lock;
    IOHandle* m_handle;

    /* Interval, in secs, at which to send heartbeats. Values below 30 seconds
        might not be too reliable, because the underlying housekeeping timer has
        around a 20 second precision. */
    int m_hb_intvl;
    time_t m_start;
    time_t m_opened;

    time_t m_hb_last;

    uint64_t m_request_id;

    char *  m_buf;
    size_t  m_bytes_avail;

    bool m_is_closing;

    event_loop & m_evl;

    bool m_is_dealer;

    jalson::json_value m_challenge; // full message

  private:
    // TODO: why two?
    std::map<int, PendingReq* > m_pend_req;
    std::map<int, PendingReq2 > m_pend_req_2;
    std::mutex m_pend_req_lock;

    std::shared_ptr< t_sid > m_session_handle;
  };

} // namespace XXX

#endif
