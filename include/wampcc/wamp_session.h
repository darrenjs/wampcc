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
#include "wampcc/tcp_socket.h"

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
struct logger;


/** Callback type used to provide a session ID for new sessions. */
typedef std::function<t_session_id()> session_id_generator_fn;

/** Callback type used to signal wamp session becomes open or closed.*/
typedef std::function<void(wamp_session&, bool is_open)> on_state_fn;

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

  enum class action
  {
    publish,      /* publish action */
    subscribe,    /* subscribe action */
    register1,    /* register action */
    call          /* call action */
  };

  struct authorized {
    bool allow;
    bool disclose;
  };

  /* auth_plan combines auth requirement plus list of supported methods */
  typedef std::tuple<mode, std::set<std::string>> auth_plan;

  /* Return the name of this authenticate provider, eg 'userdb' */
  std::function<std::string(const std::string& realm)> provider_name;

  /* Handle request for user access to realm. Must return the authentication
   * mode and a set of supported authentication methods (which are then
   * applicable if mode==authenticate). */

  // TODO: add a boolean to indicate whether the user_id was provided
  std::function<auth_plan(const std::string& user, const std::string& realm) > policy;

  /** For challenge response authentication (CRA), provide optional password
      salting parameters. If available these are added to any challenge sent to
      the peer. The same parameters must later be used during either check_cra()
      or user_secret(). Note that WAMP implementatins typically use SHA256, so
      keylen is normally 32. */
  struct cra_salt_params {
    std::string salt;
    int keylen;
    int iterations;
  };
  std::function<cra_salt_params(const std::string& realm, const std::string& user)> cra_salt;

  /* Optionally handle the wamp CRA check. This function must fetch the secret
   * associated with the user & realm, apply it to the challenge, and
   * determine if the challenge matches the response. If this is not
   * implemented then the wamp session will request the user secret and
   * perform the check itself. */
  std::function<bool(const std::string& user, const std::string& realm,
                     const std::string& challenge,
                     const std::string& response)> check_cra;

  /* Obtain the secret for given user and realm. Required if check_cra is not
   * provided. Note that the user secret can either be a naked password (if
   * cra_salt is null), or can be the derived secret (is salting is used). */
  std::function<std::string(const std::string& user,
                            const std::string& realm)> user_secret;

  /* Obtain the role for given user and realm.
   * TODO: more description
   * */
  std::function<std::string(const std::string& user,
                            const std::string& realm)> user_role;

  /* Check if the given realm, role, uri triple is allowed */
  std::function<authorized(const std::string& realm,
                const std::string& authrole,
                const std::string& uri,
                action)> authorize;

  /* Create an auth_provider object which implements a
   * no-authentication-required policy. */
  static auth_provider no_auth_required() {
    return auth_provider {
      [](const std::string&){ return "no_auth_required"; },
        [](const std::string&, const std::string&) {
          return auth_plan{mode::open,{}}; },
          nullptr, nullptr, nullptr };
  }
};

/** Collection of callbacks that a server application (i.e. one that implements
 * dealer and/or router role) will provide to handle unsolicited client
 * requests. */
struct server_msg_handler
{
  std::function<void(wamp_session&, t_request_id, std::string&, json_object&, wamp_args&)> on_call;
  std::function<void(wamp_session&, t_request_id, std::string&, json_object&, wamp_args&)> on_publish;
  std::function<void(wamp_session&, t_request_id, std::string&, json_object&)> on_register;
  std::function<void(wamp_session&, t_request_id, t_registration_id)> on_unregister;
  std::function<void(wamp_session&, t_request_id, std::string&, json_object&)> on_subscribe;
  std::function<void(wamp_session&, t_request_id, t_subscription_id)> on_unsubscribe;

  server_msg_handler();
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

struct event_info
{
  t_subscription_id subscription_id;
  json_object details;
  wamp_args args;
  void* user;
};
typedef std::function<void(wamp_session&, event_info)> on_event_fn;

struct subscribed_info
{
  t_request_id request_id;
  t_subscription_id subscription_id;
  bool was_error;
  std::string error_uri;
  void* user;

  /** Returns whether this message indicates the request was successful. */
  explicit operator bool() const noexcept { return was_error == false; }
};

/** Callback invoked when a subscribe request is successful or fails. Error
    contains the error code when the subscription is not successful.
*/
typedef std::function<void(wamp_session&, subscribed_info)> on_subscribed_fn;

struct unsubscribed_info
{
  t_request_id request_id;
  bool was_error;
  std::string error_uri;
  void* user;

  /** Returns whether this message indicates the request was successful. */
  explicit operator bool() const noexcept { return !was_error; }
};

/** Callback invoked when an unsubscription request completes. Error contains
    the error code when the subscription is not successful.
*/
typedef std::function<void(wamp_session&, unsubscribed_info)> on_unsubscribed_fn;

struct published_info
{
  t_request_id request_id;
  t_publication_id publication_id;
  bool was_error;
  std::string error_uri;
  void* user;

  /** Returns whether this message indicates the request was successful. */
  explicit operator bool() const noexcept { return was_error == false; }
};

/** Callback invoked when a publish request is successful or fails. The
    error_uri member contains the error code when unsuccessful.
*/
typedef std::function<void(wamp_session&, published_info)> on_published_fn;

/** Represent a dealer response caused by a previous CALL request. The
 * originating CALL request would have been initiated via a call of method
 * wamp_session::call(). The response could indicate success (if dealer sent
 * RESULT) or failure (if dealer sent ERROR). */
struct result_info
{
  t_request_id request_id;
  json_object additional; // holds the WAMP 'details' or 'options'
  bool was_error;
  std::string error_uri; // if was_error == true
  wamp_args args;
  void * user;

  result_info() : request_id(0), was_error(false), user(0){}

  result_info(t_request_id r, json_object op, wamp_args a, void * u) :
    request_id(r),
    additional(op),
    was_error(false),
    args(std::move(a)),
    user(u) {}

  /** Returns whether this message indicates the request was successful. */
  operator bool() const noexcept { return !was_error; }
};

typedef std::function<void(wamp_session&, result_info)> on_result_fn;

/** Represent the callee response elicited by a previous INVOCATION request,
 * made via an earlier call of method invocation().  The response could either
 * indicate success (if callee sent YIELD) or failure (if callee sent
 * ERROR). */
struct yield_info
{
  t_request_id request_id;
  json_object additional; // holds the WAMP 'details' or 'options'
  bool was_error;
  std::string error_uri; // if was_error == true
  wamp_args args;
  void * user;

  yield_info() : request_id(0), was_error(false), user(0){}

  yield_info(t_request_id r, json_object op, std::string eu, wamp_args a, void * u)
    : request_id(r),
      additional(std::move(op)),
      was_error(true),
      error_uri(std::move(eu)),
      args(std::move(a)),
      user(u)
  {}
  yield_info(t_request_id r, json_object op, wamp_args a, void * u)
    : request_id(r),
      additional(std::move(op)),
      was_error(false),
      args(std::move(a)),
      user(u)
  {}

  /** Returns whether this message indicates the request was successful. */
  operator bool() const noexcept { return !was_error; }
};

typedef std::function<void(wamp_session&, yield_info)> on_yield_fn;

/** Callback data associated with arrival of a REGISTERED wamp message. */
struct registered_info
{
  t_request_id request_id;
  t_registration_id registration_id;
  bool was_error;
  std::string error_uri;
  void * user;

  /** Returns whether this message indicates the request was successful. */
  operator bool() const noexcept { return !was_error; }
};
typedef std::function<void(wamp_session&, registered_info)> on_registered_fn;


/** Callback data associated with the response to an unregister request
 * (i.e. due to an earlier call to session::unprovide). */
struct unregistered_info
{
  t_request_id request_id;
  bool was_error;
  std::string error_uri;
  void * user;

  /** Returns whether this message indicates the request was successful. */
  operator bool() const noexcept { return !was_error; }
};
typedef std::function<void(wamp_session&, unregistered_info)> on_unregistered_fn;


/** Callback data associated with arrival of an INVOCATION wamp message.  The
 * registration_id identifies a previously registered procedure that should
 * now be invoked, using the peer provide details and arguments. */
struct invocation_info
{
  t_request_id request_id;
  t_registration_id registration_id;
  json_object details;
  wamp_args args;
  void * user;

  invocation_info()
    : request_id(0),
      registration_id(0),
      user(nullptr) {}

  invocation_info(t_request_id __request_id,
                  t_registration_id __registration_id,
                  json_object __details,
                  wamp_args __args,
                  void * __user)
    : request_id(__request_id),
      registration_id(__registration_id),
      details(std::move(__details)),
      args(std::move(__args)),
      user(__user)
  {}
};
typedef std::function<void(wamp_session&,
                           invocation_info)> on_invocation_fn;


/* TODO: refactor */
class wamp_error : public std::runtime_error
{
public:
  wamp_error(const std::string& error_uri, wamp_args wa = wamp_args())
    : std::runtime_error(error_uri),
      m_uri(error_uri),
      m_args(wa)
  {  }

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

  const std::string & error_uri() const { return m_uri; }

private:
  std::string m_uri;
  wamp_args m_args;
};


/**
   Provides a WAMP session that supports both client and server roles.

   This class provides an API for sending both client-side and server-side WAMP
   message requests and handling peer responses and requests. Communication with
   the peer uses an internal transport object and messages are serialised using a
   protcol that is selected at object creation.

   State-management
   ----------------

   A wamp_session is initially constructed using a transport object
   (e.g. tcp_socket or ssl_socket) that has recently established connection to
   the peer.  Initially the session is not logically open; it needs to progress
   though the WAMP session establishment sequence, optionally including
   authentication, before is deemed open and ready to send and receive messages.
   A client initiates the establishment sequence by calling `hello()`; when the
   sequence completes, successfully or unsuccessfully, the owner is notified via
   the on_state_fn callback.

   The `is_open()` method indicates if the logical session is open, allowing WAMP
   message requests to be made.

   Callbacks & threading
   ---------------------

   A wamp_session is a source of solicited and unsolicited callbacks,
   corresponding to state changes, asynchronous replies and peer requests.
   Callbacks must be specified at wamp_session creation and when making requests.

   Such callbacks are always delivered on the event thread owned by the wampcc
   kernel. The owner must assume a callback can be made at any time, up until the
   session has closed.

   Disposal
   --------

   A wamp_session instance is managed by std::shared_ptr. In addition to the
   shared_ptr instances held by the owner, the wampcc event thead will
   temporarily acquire a shared_ptr for the duration of a callback.

   A wamp_session that is no longer needed can be disposed of by releasing all
   managing shared_ptr objects. At this time other resources associated with the
   instance may also be released, typically these are the objects captured by the
   callback lambda functions.

   Prior to disposal of the wamp_session and associated resources, the owner
   _must_ ensure that no callbacks are either underway or imminent. Callbacks
   that occur after resources have been released results in undefined behaviour.

   To ensure callbacks are complete before commencing disposal, the owner should
   wait on the std::future returned by `closed_future()`.  This wait _must not_
   be performed during an event callback, doing so would cause self-deadlock (the
   event thread cannot wait for itself). The closed-future is also returned by
   `close()`, which additionally initiates closure of the session if not already
   closed.

   The `is_closed()` method indicates if the session is logically closed and
   callbacks are complete.
*/
class wamp_session : public std::enable_shared_from_this<wamp_session>
{
public:

  struct options
  {
    /* Duration to wait for succesful session logon. If logon is not achieved
     * before duration expires, session will be automatically closed. Default
     * value is high, due to often slow nature of websocket gateways. Zero
     * suppresses this check. */
    std::chrono::milliseconds max_pending_open;

    options()
      : max_pending_open(30000) {}
  };

  enum class mode {client, server};

  /** Create a server-mode session (i.e., the socket was accepted from a remote
   * client). A session_id_generator_fn can optionally be provided to allocate a
   * unique session ID to the session instance created. */
  static std::shared_ptr<wamp_session> create(kernel*,
                                              std::unique_ptr<tcp_socket>,
                                              on_state_fn,
                                              protocol_builder_fn,
                                              server_msg_handler,
                                              auth_provider,
                                              options = options(),
                                              void * = nullptr,
                                              session_id_generator_fn = {});

  /** Create a client-mode session (i.e., the socket was actively connected to a
   * remote server) using a protocol class as specified via the template
   * parameter. A session_id_generator_fn can optionally be provided to allocate
   * a unique session ID to the session instance created */
  template<typename T>
  static std::shared_ptr<wamp_session> create(kernel* k,
                                              std::unique_ptr<tcp_socket> sock,
                                              on_state_fn state_cb = nullptr,
                                              typename T::options protocol_options = {},
                                              wamp_session::options session_opts = {},
                                              void* user = nullptr,
                                              session_id_generator_fn id_gen_fn = {})
  {
    /* This method has taken ownership of the tcp_socket, so use a guard to
     * ensure proper close and deletion. */
    tcp_socket_guard sock_guard(sock);

    protocol_builder_fn factory_fn;
    factory_fn = [protocol_options, k](tcp_socket* sock,
                                       protocol::t_msg_cb _msg_cb,
                                       protocol::protocol_callbacks callbacks)
      {
        std::unique_ptr<protocol> up (
          new T(k, sock, _msg_cb, callbacks,
                connect_mode::active, protocol_options)
          );
        return up;
      };

    return wamp_session::create_impl(k, mode::client, sock,
                                     state_cb, factory_fn, server_msg_handler(), auth_provider(),
                                     session_opts, user, std::move(id_gen_fn));
  }

  /** Perform WAMP HELLO for a client-mode instance. Should be invoked
   * immediately following wamp_session construction. The credentials are used
   * with wampcra authentication. */
  std::future<void> hello(client_credentials);

  //@{
  /** Perform WAMP HELLO for a client-mode instance. Should be invoked
   * immediately following wamp_session construction. Does not offer to
   * authenticate with peer. */
  std::future<void> hello(const std::string& realm);
  std::future<void> hello(const std::string& realm, const std::string& userid);
  //@}

  ~wamp_session();

  /** Request graceful session close. Graceful closure involves the
   * coordinated exchange of logoff messages with the peer. Successfully
   * performing a graceful session close minimises the risk of losing any
   * final messages sent just before socket close.  The session closure will
   * complete asynchronously, because it takes time to send and receive logoff
   * messages with the peer.  The returned future can be used to wait for
   * completion of session closure.  Once closed there will be no more
   * callbacks from the session. */
  std::shared_future<void> close();

  /** Perform synchronous fast (ungraceful) session close */
  void fast_close();

  session_handle handle() { return shared_from_this(); }

  /** Determine if session is presently open. Only if this returns true should
   * the session be used for wamp tasks, such invoking remote procedures or
   * publishing to topics. */
  bool is_open() const;

  /** Determine if this session is in the closed state.  The closed state
   * implies the underlying network transport has closed, the logical-session
   * has ended, and that this instance will make no further callbacks into
   * owner code (via the callbacks earlier registered).  Only when a session
   * has reached the closed state should its owner attempt to reset or delete
   * the managing shared_ptr, and dispose of any resources associated with the
   * callbacks.  This function is not equivalent to is_open() == false. */
  bool is_closed() const;

  bool is_pending_open() const;

  /** Number of seconds since session constructed  */
  time_t time_created() const;

  /** Time since last message */
  time_t time_last() const;


  /** Authorization check for given uri and action (publish, subscribe, register, call).
   * If the uri/action combination is not authorized throw and exception 
   * Used by server-mode session */
  auth_provider::authorized authorize(const std::string& uri, auth_provider::action);

  /** Return the realm, or empty string if a realm has not yet been provided,
   * eg, in case of a server session that receives the realm from the peer. */
  const std::string& realm() const;

  /** Allow a callee application to register a procedure with a dealer. A WAMP
   * REGISTER message is sent to the connected dealer to request registration of
   * the procedure `uri`.  The success or failure of the registration attempt,
   * and requests for procedure invocation, are delivered via the callback
   * function arguments. */
  t_request_id provide(const std::string& uri,
                       json_object options,
                       on_registered_fn,
                       on_invocation_fn,
                       void * user = nullptr);

  /** Unregister a procedure. Allow a callee to request the unregister of a
   * previously registered procedure. The success or failure of the unregister
   * attempt is delivered via the callback function argument.*/
  t_request_id unprovide(t_registration_id,
                         on_unregistered_fn,
                         void * user = nullptr);

  /** Subscribe to a topic. The on_subscribed_fn callback is invoked upon success
   * or failure of the request. Subsequent topic updates which can follow a
   * successful subscription are delivered via the on_event_fn
   * callback.
   *
   * Note that while unadvised, a topic can be subscribed to more than once.
   * Doing so does not multiply the subsequent topic events, however, it is
   * the event-callback associated with the most recent subscription that is
   * used to deliver topic events.
   */
  t_request_id subscribe(const std::string& uri,
                         json_object options,
                         on_subscribed_fn,
                         on_event_fn,
                         void * user = nullptr);

  /** Unsubscribe a subscription. The subscription is identified via its WAMP
   * subscription ID.  The unsubscribed_cb callback is invoked upon success or
   * failure of the request. */
  t_request_id unsubscribe(t_subscription_id,
                           on_unsubscribed_fn,
                           void * user = nullptr);

  /** Allow a caller application to request that a dealer should attempt to
   * fulfill execution of a remote procedure.  A CALL message will be sent
   * to the connected dealer.  The response of the request will be delivered
   * via the callback function argument. */
  t_request_id call(const std::string& uri,
                    json_object options,
                    wamp_args args,
                    on_result_fn,
                    void* user_data = nullptr);

  /** Allow a publisher application to publish to a topic. A PUBLISH message
   * will be sent to the connected router.  The response of the request will
   * be delivered via the on_published_fn function, if that argument is
   * not empty. */
  t_request_id publish(const std::string& uri,
                       json_object options,
                       wamp_args args,
                       on_published_fn = nullptr,
                       void * user = nullptr);

  /** Allow a broker application to send an EVENT message. */
  void event(t_subscription_id, t_publication_id, json_object details, wamp_args args);

  /** Allow a dealer application to request invocation of a callee
   * procedure. An INVOCATION message will be send to the connected callee, to
   * request execution of a procedure identified with the
   * `registration_id`. The response from the request will be delivered via
   * the callback function argument. */
  t_request_id invocation(t_registration_id registration_id,
                          const json_object& options,
                          wamp_args args,
                          on_yield_fn,
                          void * user = nullptr);

  /** Obtain the session's the unique ID. Values begin from 1. */
  t_session_id unique_id() const { return m_sid; }

  /** Return the session mode, which indicates whether this session was
   * created and operates as a client or a server. */
  mode session_mode() const { return m_session_mode; }

  /** Return the name of the wire protocol used by the session. */
  const char* protocol_name() const { return m_proto->name(); }

  /** Obtain the future which is set upon closure of the session.  Waiting on
   * this future is one mechanism which allows a thread to detect when the
   * session has been closed. */
  std::shared_future<void> closed_future() const { return m_shfut_has_closed; }

  /** Reply to a REGISTER request with a REGISTERED mesage to indicate the
   * request is successful. The associated REGISTER request is provided via
   * the request_id parameter. */
  void registered(t_request_id request_id, t_registration_id);

  /** Return the authid associated with this session, if one has been
   * provided (use has_authid() to determine if provided). */
  std::string authid() const;

  /** Return whether an authid is associated with this session. */
  bool has_authid() const;

  /** Return the authrole associated with this session. */
  std::string authrole() const;

  /** Return the agent description associated with this session, if one has been
   * provided (use has_agent() to determine if provided). */
  std::string agent() const;

  /** Return whether an agent description is associated with this session. */
  bool has_agent() const;

  //@{
  /** Reply to a REGISTER request with an ERROR message to indicate the
   * corresponding registration request could not be fulfilled. */
  void register_error(t_request_id, std::string error);
  void register_error(t_request_id, std::string error, json_object details);
  //@}

  /** Reply to an UNREGISTER request with an UNREGISTERED message to indicate
   * success. */
  void unregistered(t_request_id);

  //@{
  /** Reply to an UNREGISTER request with an ERROR message to indicate
   * failure. */
  void unregister_error(t_request_id, std::string error);
  void unregister_error(t_request_id, std::string error, json_object details);
  //@}

  //@{
  /** Reply to a CALL request with a RESULT message to indicate success. */
  void result(t_request_id);
  void result(t_request_id, json_array);
  void result(t_request_id, json_array, json_object);
  void result(t_request_id, json_object details);
  void result(t_request_id, json_object details, json_array);
  void result(t_request_id, json_object details, json_array, json_object);
  //@}

  //@{
  /** Reply to a CALL request with an ERROR message to indicate failure. */
  void call_error(t_request_id, std::string error);
  void call_error(t_request_id, std::string error, json_array);
  void call_error(t_request_id, std::string error, json_array, json_object);
  void call_error(t_request_id, std::string error, json_object details);
  void call_error(t_request_id, std::string error, json_object details, json_array);
  void call_error(t_request_id, std::string error, json_object details, json_array, json_object);
  //@}

  //@{
  /** Reply to an INVOCATION request with a YIELD message to indicate the
   * invocation has been successful. The request_id of the corresponding
   * INVOCATION request must be provided. */
  void yield(t_request_id);
  void yield(t_request_id, json_array);
  void yield(t_request_id, json_array, json_object);
  void yield(t_request_id, json_object options);
  void yield(t_request_id, json_object options, json_array);
  void yield(t_request_id, json_object options, json_array, json_object);
  //@}

  //@{
  /** Reply to an INVOCATION request with an ERROR message to indicate the
   * invocation has failed. The request_id of the corresponding INVOCATION
   * request must be provided. */
  void invocation_error(t_request_id, std::string error);
  void invocation_error(t_request_id, std::string error, json_array);
  void invocation_error(t_request_id, std::string error, json_array, json_object);
  void invocation_error(t_request_id, std::string error, json_object details);
  void invocation_error(t_request_id, std::string error, json_object details, json_array);
  void invocation_error(t_request_id, std::string error, json_object details, json_array, json_object);
  //@}

  /** Reply to a SUBSCRIBE request with a SUBSCRIBED message to indicate the
   * subscription request has been successful. */
  void subscribed(t_request_id, t_subscription_id);

  //@{
  /** Reply to a SUBSCRIBE request with an ERROR message to indicate the
   * subscription request could not be fulfilled. */
  void subscribe_error(t_request_id, std::string error);
  void subscribe_error(t_request_id, std::string error, json_object details);
  //@}

  /** Reply to an UNSUBSCRIBE request with an UNSUBSCRIBED message to
   * indicate the subscription request has been successful. */
  void unsubscribed(t_request_id);

  //@{
  /** Reply to an UNSUBSCRIBE request with an ERROR message to indicate the
   * unsubscription request could not be fulfilled. */
  void unsubscribe_error(t_request_id, std::string error);
  void unsubscribe_error(t_request_id, std::string error, json_object details);
  //@}

  /** Reply to a PUBLISH request with a PUBLISHED message to indicate the
   * publication request has been successful. */
  void published(t_request_id, t_publication_id);

  //@{
  /** Reply to a PUBLISH request with an ERROR message to indicate the
   * publication request could not be fulfilled. */
  void publish_error(t_request_id, std::string error);
  void publish_error(t_request_id, std::string error, json_object details);
  //@}

  /** Access user data */
  void * user() const { return m_user; }

  /** Modify user data **/
  void * & user() { return m_user; }

  //@{
  /** Obtain the tcp socket underlying this session */
  const wampcc::tcp_socket* socket() const { return m_socket.get(); }
  wampcc::tcp_socket* socket() { return m_socket.get(); }
  //@}

private:

  void proto_close(); // for tests

  static std::shared_ptr<wamp_session> create_impl(kernel*,
                                                   mode,
                                                   std::unique_ptr<tcp_socket>&,
                                                   on_state_fn,
                                                   protocol_builder_fn ,
                                                   server_msg_handler,
                                                   auth_provider,
                                                   wamp_session::options,
                                                   void*,
                                                   session_id_generator_fn);

  wamp_session(kernel*,
               mode,
               std::unique_ptr<tcp_socket>,
               on_state_fn,
               server_msg_handler,
               auth_provider,
               wamp_session::options,
               void* user,
               session_id_generator_fn);

  wamp_session(const wamp_session&) = delete;
  wamp_session& operator=(const wamp_session&) = delete;

  void io_on_read(char*, size_t);
  void io_on_error(uverr);
  void decode_and_process(char*, size_t len);
  void process_message(json_array&, json_uint_t);
  void handle_exception();

  void update_state_for_outbound(const json_array& msg);

  void send_msg(const json_array&);

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

  t_session_id m_sid;
  std::string m_log_prefix;
  std::unique_ptr<tcp_socket> m_socket;

  mode m_session_mode;

  std::promise<void> m_has_closed;
  std::shared_future<void> m_shfut_has_closed;

  time_t m_time_create;
  time_t m_time_last_msg_recv;

  mutable std::mutex m_request_lock;
  t_request_id m_next_request_id;

  std::function< std::string() > m_client_secret_fn;

  std::string m_realm;
  mutable std::mutex m_realm_lock;
  std::pair<bool, std::string> m_authid; // .first ==> tells if present
  std::pair<bool, std::string> m_agent;  // .first ==> tells if present
  std::string m_challenge;

  std::string m_authrole;
  mutable std::mutex m_authrole_lock;

  auth_provider m_auth_proivder;
  bool m_server_requires_auth;

  on_state_fn m_notify_state_change_fn;

  void process_inbound_register(json_array &);
  void process_inbound_registered(json_array &);
  void process_inbound_unregister(json_array &);
  void process_inbound_unregistered(json_array &);
  void process_inbound_invocation(json_array &);
  void process_inbound_subscribed(json_array &);
  void process_inbound_unsubscribed(json_array &);
  void process_inbound_published(json_array &);
  void process_inbound_event(json_array &);
  void process_inbound_result(json_array &);
  void process_inbound_error(json_array &);
  void process_inbound_call(json_array &);
  void process_inbound_yield(json_array &);
  void process_inbound_publish(json_array &);
  void process_inbound_subscribe(json_array &);
  void process_inbound_unsubscribe(json_array &);
  void process_inbound_goodbye(json_array &);
  void process_inbound_abort(json_array &);

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

  std::future<void> hello_common(const std::string& realm,
                                 std::pair<bool, std::string> user);

  void check_hello(const std::string& realm,
                   std::pair<bool, std::string> auth);

  server_msg_handler m_server_handler;

  struct register_request;
  struct unregister_request;
  struct subscribe_request;
  struct unsubscribe_request;
  struct publish_request;
  struct call_request;
  struct invocation_request;

  /* Track pending requests made by this session. */
  mutable std::mutex m_pending_lock;
  std::map<t_request_id, subscribe_request>   m_pending_subscribe;
  std::map<t_request_id, unsubscribe_request> m_pending_unsubscribe;
  std::map<t_request_id, publish_request>     m_pending_publish;
  std::map<t_request_id, register_request>    m_pending_register;
  std::map<t_request_id, unregister_request>  m_pending_unregister;
  std::map<t_request_id, call_request>        m_pending_call;
  std::map<t_request_id, invocation_request>  m_pending_invocation;

  // No locking required, since procedure and subscriptions managed only on EV
  // thread
  struct procedure;
  struct subscription;
  std::map<t_registration_id, procedure> m_procedures;
  std::map<t_subscription_id, subscription> m_subscriptions;

  std::unique_ptr<protocol> m_proto;

  std::promise< void > m_promise_on_open;

  options m_options;

  // arbitrary user data
  void* m_user;
};

} // namespace wampcc

#endif
