#ifndef XXX_SESSION_H
#define XXX_SESSION_H

#include "XXX/types.h"
#include "XXX/io_listener.h"
#include "XXX/protocol.h"

#include <jalson/jalson.h>

#include <map>
#include <mutex>
#include <memory>
#include <future>

namespace XXX {

  class protocol;
  class wamp_session;


  typedef std::function< void(wamp_args, std::unique_ptr<std::string> ) > wamp_invocation_reply_fn;
  typedef std::function< void(session_handle, bool) > session_state_fn;

  struct auth_provider
  {
    std::function<std::string(const std::string& realm)> provider_name;
    std::function<bool(const std::string& user, const std::string& realm)> permit_user_realm;
    std::function<std::string(const std::string& user, const std::string& realm)> get_user_secret;
  };

  struct server_msg_handler
  {
    std::function<void(wamp_session*, std::string uri, wamp_args, wamp_invocation_reply_fn)> inbound_call;
    std::function<void(wamp_session*, std::string uri, jalson::json_object, wamp_args)> handle_inbound_publish;
    std::function<uint64_t (std::weak_ptr<wamp_session>, std::string realm, std::string uri)> inbound_register;
    std::function<uint64_t (wamp_session*, t_request_id, std::string uri, jalson::json_object&)> inbound_subscribe;
    std::function<void (wamp_session*, t_request_id, t_subscription_id)> inbound_unsubscribe;
  };

  class kernel;
  class io_handle;
  struct logger;


  struct client_credentials
  {
    std::string realm;
    std::string authid;
    std::vector< std::string > authmethods;
    std::function< std::string() > secret_fn;
  };

  enum subscription_event_type
  {
    e_sub_failed,
    e_sub_start,
    e_sub_update,
    e_sub_end
  };

  typedef std::function<void(subscription_event_type evtype,
                             const std::string& uri,
                             const jalson::json_object& details,
                             const jalson::json_array& args_list,
                             const jalson::json_object& args_dict,
                             void* user) > subscription_cb;


  typedef std::function< void (wamp_call_result) > wamp_call_result_cb;


  // Needs to support needs of service providers (rpc & topics), and service
  // consumers (rpc callers, and subscribers)
  class wamp_session : public std::enable_shared_from_this<wamp_session>,
                       public io_listener
  {
  public:

    /** Create a server side session (i.e., the socket was accepted from a
     * remote client). */
    static std::shared_ptr<wamp_session> create(kernel&,
                                                std::unique_ptr<io_handle>,
                                                session_state_fn,
                                                protocol_builder_fn ,
                                                server_msg_handler,
                                                auth_provider);

    /** Create a client side session (i.e., the socket was actively connected to
     * remote server). */
    template<typename T>
    static std::shared_ptr<wamp_session> create(kernel& k,
                                                std::unique_ptr<io_handle> socket,
                                                session_state_fn state_cb,
                                                typename T::options _options)
    {
      protocol_builder_fn factory_fn;

      factory_fn = [_options](io_handle* socket, protocol::t_msg_cb _msg_cb)
        {
          std::unique_ptr<protocol> up (
            new T(socket, _msg_cb,
                  protocol::connection_mode::eActive, _options)
            );
          return up;
        };

      return wamp_session::create(k, std::move(socket), state_cb, factory_fn, {}, {});
    }


    ~wamp_session();

    void send_msg(jalson::json_array&, bool final=false);

    /** Request asynchronous close of the session */
    std::shared_future<void> close();

    session_handle handle() { return shared_from_this(); }

    bool is_open() const;
    bool is_pending_open() const;

    void initiate_handshake(client_credentials);

    /* Number of seconds since session constructed  */
    int duration_since_creation() const;

    /* Time since last message */
    int duration_since_last() const;

    /* Does this session use heartbeats? */
    bool uses_heartbeats() const;

    /** Return the realm, or empty string if a realm has not yet been provided,
     * eg, in case of a passive session that receives the realm from remote
     * peer. */
    std::string realm() const;

    int hb_interval_secs() const { return m_hb_intvl; }


    t_request_id provide(std::string uri,
                         const jalson::json_object& options,
                         rpc_cb cb,
                         void * data);

    t_request_id subscribe(const std::string& uri,
                           const jalson::json_object& options,
                           subscription_cb cb,
                           void * user);

    t_request_id call(std::string uri,
                      const jalson::json_object& options,
                      wamp_args args,
                      wamp_call_result_cb user_cb,
                      void* user_data);

    t_request_id publish(std::string uri,
                         const jalson::json_object& options,
                         wamp_args args);

    t_request_id invocation(uint64_t registration_id,
                            const jalson::json_object& options,
                            wamp_args args,
                            wamp_invocation_reply_fn);

    t_sid unique_id() const { return m_sid; }

    bool is_passive() const;

    const char* protocol_name() const { return m_proto->name(); }

  private:

    wamp_session(kernel&,
                 std::unique_ptr<io_handle>,
                 session_state_fn state_cb,
                 protocol_builder_fn protocol_builder,
                 server_msg_handler,
                 auth_provider);

    wamp_session(const wamp_session&) = delete;
    wamp_session& operator=(const wamp_session&) = delete;

    void io_on_close() override;
    void io_on_read(char*, size_t) override;
    void decode_and_process(char*, size_t len);
    void process_message(unsigned int, jalson::json_array&);
    void handle_exception();

    void update_state_for_outbound(const jalson::json_array& msg);

    friend class io_handle;

    enum SessionState
    {
      eInit = 0,

      // for active client
      eRecvHello,
      eSentChallenge,
      eRecvAuth,

      // next are client state values
      eSentHello,
      eRecvChallenge,
      eSentAuth,

      // main states
      eOpen,
      eClosing,
      eClosed,

      eStateMax
    } m_state;

    void change_state(SessionState expected, SessionState next);

    void handle_HELLO(jalson::json_array& ja);
    void handle_CHALLENGE(jalson::json_array& ja);
    void handle_AUTHENTICATE(jalson::json_array& ja);

    void notify_session_open();
    static const char* state_to_str(wamp_session::SessionState);


    logger & __logger; /* name chosen for log macros */
    kernel& m_kernel;

    uint64_t m_sid;

    std::unique_ptr<io_handle> m_handle;

    std::promise<void> m_has_closed;
    std::shared_future<void> m_shfut_has_closed;

    /* Interval, in secs, at which to send heartbeats. Values below 30 seconds
        might not be too reliable, because the underlying housekeeping timer has
        around a 20 second precision. */
    int m_hb_intvl;
    time_t m_time_create;

    time_t m_time_last_msg_recv;

    mutable std::mutex m_request_lock;
    t_request_id m_next_request_id;

    std::function< std::string() > m_client_secret_fn;

    std::string m_realm;
    std::string m_authid;
    std::string m_challenge;
    mutable std::mutex m_realm_lock;

    auth_provider m_auth_proivder;

    session_state_fn m_notify_state_change_fn;

    void process_inbound_registered(jalson::json_array &);
    void process_inbound_invocation(jalson::json_array &);
    void process_inbound_subscribed(jalson::json_array &);
    void process_inbound_event(jalson::json_array &);
    void process_inbound_result(jalson::json_array &);
    void process_inbound_error(jalson::json_array &);
    void process_inbound_call(jalson::json_array &);
    void process_inbound_yield(jalson::json_array &);
    void process_inbound_publish(jalson::json_array &);
    void process_inbound_subscribe(jalson::json_array &);
    void process_inbound_unsubscribe(jalson::json_array &);
    void process_inbound_register(jalson::json_array &);

    void invocation_yield(int request_id,
                          wamp_args args);

    void reply_with_error(int request_type,
                          int request_id,
                          wamp_args args,
                          std::string error_uri);


    void drop_connection(std::string);

    bool user_cb_allowed() const { return m_state != eClosed; }

    server_msg_handler m_server_handler;

    struct procedure
    {
      std::string uri;
      rpc_cb user_cb;
      void * user_data;
    };

    struct subscription
    {
      std::string uri;
      subscription_cb user_cb;
      void * user_data;
    };

    struct wamp_call
    {
      std::string rpc;
      wamp_call_result_cb user_cb;
      void* user_data;
      wamp_call() : user_data( nullptr ) { }
    };

    struct wamp_invocation
    {
      wamp_invocation_reply_fn reply_fn;
    };


    mutable std::mutex m_pending_lock;
    std::map<t_request_id, subscription>    m_pending_subscribe;
    std::map<t_request_id, procedure>       m_pending_register;
    std::map<t_request_id, wamp_call>       m_pending_call;
    std::map<t_request_id, wamp_invocation> m_pending_invocation;

    // TODO: procedures -- not currently locked, however, need to add locking once
    // unprovide() is added, and if it is implemented synchronously.
    std::map<t_request_id, procedure> m_procedures;
    std::map<t_subscription_id, subscription> m_subscriptions;

    std::function<int()> m_hb_func;
    std::unique_ptr<protocol> m_proto;
  };

} // namespace XXX

#endif
