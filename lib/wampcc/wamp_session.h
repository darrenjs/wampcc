/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_SESSION_H
#define WAMPCC_SESSION_H

#include "wampcc/types.h"
#include "wampcc/protocol.h"
#include "wampcc/error.h"
#include "wampcc/json.h"

#include <map>
#include <mutex>
#include <memory>
#include <future>
#include <set>

namespace wampcc {

  class protocol;
  class wamp_session;
  class kernel;
  class pubsub_man;
  class tcp_socket;
  struct logger;

  typedef std::function< void(wamp_args, std::unique_ptr<std::string> ) > wamp_invocation_reply_fn;
  typedef std::function< void(std::weak_ptr<wamp_session>, bool) > state_fn;

  /** Handler interface for server-side authentication.  An instance of
   * auth_provider must be provided to each server-side wamp_session, which
   * allows that session to authenticate its peer. */
  struct auth_provider
  {
    enum class mode
    {
      forbidden,    /* user not permitted */
      open,         /* user allowed without authentication */
      authenticate  /* user must authenticate */
    };

    /* auth_plan combines auth requirement plus list of supported methods */
    typedef std::tuple<mode, std::set<std::string>> auth_plan;

    /* Return the name of this authenticate provider, eg 'userdb' */
    std::function<std::string(const std::string& realm)> provider_name;

    /* Handle request for user access to realm. Must return the authentication
     * mode and a set of supported authentication methods (which are then
     * applicable if mode==authenticate). */
    std::function<
      auth_plan
      (const std::string& user, const std::string& realm) > policy;

    /* Optionally handle the wamp CRA check. This function must fetch the secret
     * associated with the user & realm, apply it to the challenge, and
     * determine if the challenge matches the response. If this is not
     * implemented then the wamp session will request the user secret and
     * perform the check itself. */
    std::function<bool(const std::string& user, const std::string& realm,
                       const std::string& challenge,
                       const std::string& response)> check_cra;

    /* Obtain the secret for given user and realm. Required if check_cra is not
     * provided. */
    std::function<std::string(const std::string& user,
                              const std::string& realm)> user_secret;

    /* Create an auth_provider object which implements a
     * no-authentication-required policy. */
    static auth_provider no_auth_required() {
      return auth_provider {
        [](const std::string&){ return "no_auth_required"; },
        [](const std::string&, const std::string&) {
          return auth_plan{mode::open,{}}; },
          nullptr, nullptr };
    }
  };

  struct server_msg_handler
  {
    std::function<void(wamp_session*, std::string, wamp_args, wamp_invocation_reply_fn)> inbound_call;
    std::function<void(wamp_session*, std::string uri, json_object, wamp_args)> handle_inbound_publish;
    std::function<uint64_t (std::weak_ptr<wamp_session>, std::string realm, std::string uri)> inbound_register;
    std::function<uint64_t (wamp_session*, t_request_id, std::string uri, json_object&)> inbound_subscribe;
    std::function<void (wamp_session*, t_request_id, t_subscription_id)> inbound_unsubscribe;
  };

  struct client_credentials
  {
    std::string realm;
    std::string authid;
    std::vector< std::string > authmethods;
    std::function< std::string() > secret_fn;

    client_credentials() = default;
    client_credentials(std::string realm_) : realm(std::move(realm_)) {}
  };

  struct wamp_subscription_event
  {
    t_subscription_id subscription_id;
    json_object details;
    wamp_args args;
    void* user;
  };
  typedef std::function< void (wamp_subscription_event) > subscription_event_cb;

  struct wamp_subscribed
  {
    t_request_id request_id;
    std::string uri;
    t_subscription_id subscription_id;
    bool was_error;
    std::string error_uri;

    /** Check if this result indicates a success, i.e. not an error */
    explicit operator bool() const noexcept { return was_error == false; }
  };

  /** Callback invoked when a subscribe request is successful or fails. Error
      contains the error code when the subscription is not successful.
  */
  typedef std::function<void (wamp_subscribed&) > subscribed_cb;

  /** Callback invoked when an unsubscription request completes. Error contains
      the error code when the subscription is not successful.
  */
  typedef std::function< void (t_request_id,
                               bool success,
                               std::string error) > unsubscribed_cb;

  struct wamp_call_result
  {
    t_request_id reqid;    /* protocol ID that was used */
    std::string procedure;
    bool was_error;
    std::string error_uri; // if was_error == true
    json_object details;
    wamp_args args;
    void * user;

    wamp_call_result()
      : reqid(0),
        was_error(false),
        user(0){}

    /** Check if this result indicates a success, i.e. not an error */
    explicit operator bool() const noexcept { return  was_error == false; }
  };

  typedef std::function< void (wamp_call_result) > wamp_call_result_cb;

  typedef std::function<void(bool is_good, std::string error_uri)> result_cb;


  /** Aggregate passed on RPC invocation. */
  struct wamp_invocation
  {
    wamp_args   args;
    json_object details;
    void *      user = nullptr;
    std::function<void(json_array, json_object)> yield_fn;
    std::function<void(std::string, json_array, json_object)> error_fn;

    /* Wrappers to yield_fn */
    void yield() { yield_fn({}, {}); }
    void yield(json_array arr) { yield_fn(std::move(arr), {}); }
    void yield(json_object obj) { yield_fn({}, std::move(obj)); }
    void yield(json_array arr, json_object obj) { yield_fn(std::move(arr), std::move(obj)); }

    /* Wrapper to error_fn */
    void error(std::string txt) { error_fn(std::move(txt), {}, {}); }
    void error(std::string txt, json_array arr) { error_fn(std::move(txt), std::move(arr), {}); }
    void error(std::string txt, json_object obj) { error_fn(std::move(txt), {}, std::move(obj)); }
    void error(std::string txt, json_array arr, json_object obj) { error_fn(std::move(txt), std::move(arr), std::move(obj)); }

    wamp_invocation() : user(nullptr) {}
  };

  typedef std::function<void(wamp_invocation&) > rpc_cb;

  class wamp_error : public std::runtime_error
  {
  public:
    wamp_error(const char* error_uri, const char* what, wamp_args wa = wamp_args())
      : std::runtime_error(what),
        m_uri(error_uri),
        m_args(wa)
    {  }

    wamp_error(const char* error_uri, wamp_args wa = wamp_args())
      : std::runtime_error(error_uri),
        m_uri(error_uri),
        m_args(wa)
    {  }

    wamp_args& args() { return m_args; }
    const wamp_args& args() const { return m_args; }

    const std::string & error_uri() { return m_uri; }

  private:
    std::string m_uri;
    wamp_args m_args;
  };


  // Needs to support needs of service providers (rpc & topics), and service
  // consumers (rpc callers, and subscribers)
  class wamp_session : public std::enable_shared_from_this<wamp_session>
  {
  public:

    struct options
    {
      std::chrono::milliseconds max_pending_open { 10000 };
    };

    enum class mode {client, server};

    /** Create a server side session (i.e., the socket was accepted from a
     * remote client). */
    static std::shared_ptr<wamp_session> create(kernel*,
                                                std::unique_ptr<tcp_socket>,
                                                state_fn,
                                                protocol_builder_fn,
                                                server_msg_handler,
                                                auth_provider);

    /** Create a client side session (i.e., the socket was actively connected to
     * a remote server) using a protocol class as specified via the template
     * parameter. */
    template<typename T>
    static std::shared_ptr<wamp_session> create(kernel* k,
                                                std::unique_ptr<tcp_socket> socket,
                                                state_fn state_cb = nullptr,
                                                typename T::options protocol_options = {})
    {
      protocol_builder_fn factory_fn;
      factory_fn = [protocol_options, k](tcp_socket* socket,
                                         protocol::t_msg_cb _msg_cb,
                                         protocol::protocol_callbacks callbacks)
        {
          std::unique_ptr<protocol> up (
            new T(k, socket, _msg_cb, callbacks,
                  connect_mode::active, protocol_options)
            );
          return up;
        };

      return wamp_session::create_impl(k, mode::client, std::move(socket),
                                       state_cb, factory_fn, server_msg_handler(), auth_provider());
    }

    /** Should be called client session once the session has been created, to
     * begin the HELLO sequence. */
    std::future<void> initiate_hello(client_credentials);

    ~wamp_session();

    /** Request asynchronous graceful session close */
    std::shared_future<void> close();

    /** Perform synchronous fast (ungraceful) session close */
    void fast_close();

    session_handle handle() { return shared_from_this(); }

    /** Determine if session is presently open. Only if this returns true should
     * the session be used for wamp tasks, such invoking remote procedures or
     * publishing to topics. */
    bool is_open() const;

    /** Determine if session is completey closed.  Note that intermediate states
     * (such as closing, closing_wait etc) will return false.  Only use
     * is_closed() to determine final session closure.  This function is not
     * equivalent to is_open() == false. */
    bool is_closed() const;

    bool is_pending_open() const;

    /** Number of seconds since session constructed  */
    time_t time_created() const;

    /** Time since last message */
    time_t time_last() const;

    /** Return the realm, or empty string if a realm has not yet been provided,
     * eg, in case of a server session that receives the realm from the peer. */
    const std::string& realm() const;

    /** DEPRECATED.  This method will be removed in later wampcc version.  It is
     * replaced with an alternative provide() method that accepts an additiona
     * result_cb parameter. */
    t_request_id provide(std::string uri,
                         const json_object& options,
                         rpc_cb cb,
                         void * data = nullptr);

    /** Register a remote procedure with specified URI and wamp options.  Two
     * callbacks are used: on_result & on_call. The on_result lambda is called
     * upon success/failure of the registration request.  The on_invoke lambda
     * is called when a WAMP invocation request arrives to invoke the
     * procedure. */
    t_request_id provide(std::string uri,
                         const json_object& options,
                         result_cb on_result,
                         rpc_cb on_invoke,
                         void * data = nullptr);

    /** Subscribe to a topic. The subscribed_cb callback is invoked upon success
     * or failure of the request. Subsequent topic updates which can follow a
     * successful subscription are delivered via the subscription_event_cb
     * callback.
     *
     * Note that while unadvised, a topic can be subscribed to more than once.
     * Doing so does not multiply the subsequent topic events, however, it is
     * the event-callback associated with the most recent subscription that is
     * used to deliver topic events.
     */
    t_request_id subscribe(std::string uri,
                           json_object options,
                           subscribed_cb,
                           subscription_event_cb cb,
                           void * user = nullptr);

    /** Unsubscribe a subscription. The subscription is identified via its WAMP
     * subscription ID.  The unsubscribed_cb callback is invoked upon success or
     * failure of the request. */
    t_request_id unsubscribe(t_subscription_id,
                             unsubscribed_cb,
                             void * user = nullptr);

    t_request_id call(std::string uri,
                      const json_object& options,
                      wamp_args args,
                      wamp_call_result_cb user_cb,
                      void* user_data = nullptr);

    t_request_id publish(std::string uri,
                         const json_object& options,
                         wamp_args args);

    t_request_id invocation(uint64_t registration_id,
                            const json_object& options,
                            wamp_args args,
                            wamp_invocation_reply_fn);

    /** Obtain the unique ID for the session. Values begin from 1. */
    t_sid unique_id() const { return m_sid; }

    /** Return the session mode, which indicates whether this session was
     * created and operates as a client or a server. */
    mode session_mode() const { return m_session_mode; }

    /** Return the name of the wire protocol used by the session. */
    const char* protocol_name() const { return m_proto->name(); }

    /** Obtain the future which is set upon closure of the session.  Waiting on
     * this future is one mechanism which allows a thread to detect when the
     * session has been closed. */
    std::shared_future<void> closed_future() const { return m_shfut_has_closed; }

  private:;

    void proto_close(); // for tests

    static std::shared_ptr<wamp_session> create_impl(kernel*,
                                                     mode,
                                                     std::unique_ptr<tcp_socket>,
                                                     state_fn,
                                                     protocol_builder_fn ,
                                                     server_msg_handler,
                                                     auth_provider);

    wamp_session(kernel*,
                 mode,
                 std::unique_ptr<tcp_socket>,
                 state_fn,
                 server_msg_handler,
                 auth_provider);

    wamp_session(const wamp_session&) = delete;
    wamp_session& operator=(const wamp_session&) = delete;

    void io_on_read(char*, size_t);
    void io_on_error(uverr);
    void decode_and_process(char*, size_t len);
    void process_message(json_array&, json_uint_t);
    void handle_exception();

    void update_state_for_outbound(const json_array& msg);

    void send_msg(json_array&);

    void upgrade_protocol(std::unique_ptr<protocol>&);

    friend class tcp_socket;
    friend class pubsub_man;

    enum class state
    {
      init = 1,

      recv_hello,      //
      sent_challenge,  // server only
      recv_auth,       //

      sent_hello,      //
      recv_challenge,  // client only
      sent_auth,       //

      open,
      closing_wait,    // server & client
      closing,
      closed
    } m_state;
    mutable std::mutex m_state_lock;

    void change_state(state expected, state next);
    void change_state(state expecte1, state expecte2, state next);
    void terminate(std::lock_guard<std::mutex>&);
    void transition_to_closed();

    void handle_HELLO(json_array& ja);
    void handle_CHALLENGE(json_array& ja);
    void handle_AUTHENTICATE(json_array& ja);
    void send_WELCOME();

    void notify_session_open();
    static const char* to_string(wamp_session::state);

    logger & __logger; /* name chosen for log macros */
    kernel* m_kernel;

    uint64_t m_sid;
    std::string m_log_prefix;
    std::unique_ptr< tcp_socket> m_socket;

    mode m_session_mode;

    std::promise<void> m_has_closed;
    std::shared_future<void> m_shfut_has_closed;

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
    bool m_server_requires_auth;

    state_fn m_notify_state_change_fn;

    void process_inbound_registered(json_array &);
    void process_inbound_invocation(json_array &);
    void process_inbound_subscribed(json_array &);
    void process_inbound_unsubscribed(json_array &);
    void process_inbound_event(json_array &);
    void process_inbound_result(json_array &);
    void process_inbound_error(json_array &);
    void process_inbound_call(json_array &);
    void process_inbound_yield(json_array &);
    void process_inbound_publish(json_array &);
    void process_inbound_subscribe(json_array &);
    void process_inbound_unsubscribe(json_array &);
    void process_inbound_register(json_array &);
    void process_inbound_goodbye(json_array &);
    void process_inbound_abort(json_array &);

    void invocation_yield(t_request_id request_id,
                          wamp_args args);

    void reply_with_error(msg_type request_type,
                          t_request_id request_id,
                          wamp_args args,
                          std::string error_uri);

    json_array build_goodbye_message(std::string);
    json_array build_abort_message(std::string);

    void drop_connection(std::string);

    enum class close_event {local_request, recv_abort, recv_goodbye, sock_eof, protocol_closed}; //rename, local_request
    static const char* to_string(close_event v);

    void schedule_terminate_on_timeout(std::chrono::milliseconds, bool);
    void drop_connection_impl(std::string, std::lock_guard<std::mutex>&, close_event);

    bool user_cb_allowed() const;

    server_msg_handler m_server_handler;

    struct procedure
    {
      std::string uri;
      result_cb on_result;
      rpc_cb user_cb;
      void * user_data;
    };

    struct subscribe_request
    {
      std::string uri;
      subscribed_cb request_cb;
      subscription_event_cb event_cb;
      void * user_data;
    };

    struct unsubscribe_request
    {
      unsubscribed_cb request_cb;
      t_subscription_id subscription_id;
      void * user_datax;
    };

    struct subscription
    {
      subscription_event_cb event_cb;
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
    std::map<t_request_id, subscribe_request>   m_pending_subscribe;
    std::map<t_request_id, unsubscribe_request> m_pending_unsubscribe;
    std::map<t_request_id, procedure>           m_pending_register;
    std::map<t_request_id, wamp_call>           m_pending_call;
    std::map<t_request_id, wamp_invocation>     m_pending_invocation;

    // No locking required, since procedure and subscriptions managed only on EV
    // thread
    std::map<t_request_id, procedure> m_procedures;
    std::map<t_subscription_id, subscription> m_subscriptions;

    std::unique_ptr<protocol> m_proto;

    std::promise< void > m_promise_on_open;

    options m_options;
  };

} // namespace wampcc

#endif
