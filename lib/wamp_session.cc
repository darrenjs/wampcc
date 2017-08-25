/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wamp_session.h"

#include "wampcc/tcp_socket.h"
#include "wampcc/protocol.h"
#include "wampcc/rpc_man.h"
#include "wampcc/event_loop.h"
#include "wampcc/log_macros.h"
#include "wampcc/utils.h"
#include "wampcc/kernel.h"
#include "wampcc/rawsocket_protocol.h"
#include "wampcc/io_loop.h"

#include <algorithm>
#include <memory>
#include <iomanip>
#include <iostream>
#include <iterator>

#include <string.h>
#include <assert.h>

template<typename T>
static bool is_in(T t, T v) {
  return t == v;
}

template<typename T, typename... Args>
static bool is_in(T t, T v, Args... args) {
  return  t==v ||  is_in(t,args...);
}

namespace wampcc {

  struct wamp_session::procedure
  {
    std::string uri;
    on_registered_fn registered_cb;
    on_invocation_fn invocation_cb;
    void* user;
  };

  struct wamp_session::subscribe_request
  {
    std::string uri;
    on_subscribed_fn request_cb;
    on_event_fn event_cb;
    void* user;
  };

  struct wamp_session::unsubscribe_request
  {
    on_unsubscribed_fn user_cb;
    t_subscription_id subscription_id;
    void* user;
  };

  struct wamp_session::subscription
  {
    on_event_fn event_cb;
    void* user;
  };

  struct wamp_session::wamp_call
  {
    std::string rpc;
    on_result_fn user_cb;
    void* user;
  };

  struct wamp_session::wamp_invocation
  {
    on_yield_fn reply_fn;
    void* user;
  };


/* Static checks to ensure efficient operations are supported */
static_assert(std::is_copy_constructible<wamp_args>::value, "check failed");
static_assert(std::is_copy_assignable<wamp_args>::value, "check failed");

static_assert(std::is_move_constructible<wamp_args>::value, "check failed");
static_assert(std::is_move_assignable<wamp_args>::value, "check failed");

#ifndef _WIN32
static_assert(std::is_nothrow_move_constructible<wamp_args>::value, "check failed");
#endif


/* Timeout used when a session closure sequence has begun but not completed, and
   will result in the underlying socket being forcefully close. Also the timeout
   that server-side uses to close a connect (with expectation that client has
   closed the session in that interval). */
std::chrono::milliseconds close_timeout(500);

/** Exception class used to indicate failure of authentication. */
class auth_error : public std::runtime_error
{
public:

 auth_error(const std::string& __uri, const std::string& __text)
  : std::runtime_error( __text ),
    m_uri( __uri )
  {
  }

  const std::string& error_uri() const { return m_uri; }

private:
  std::string m_uri;
};


static std::atomic<t_session_id> m_next_id(1); // start at 1, so that 0 implies invalid ID
static t_session_id generate_unique_session_id()
{
  return m_next_id++;
}


static std::string generate_log_prefix(uint64_t i)
{
  std::ostringstream oss;
  oss << "session #" << i << " ";
  return oss.str();
}

static t_request_id extract_request_id(json_array & msg, int index)
{
  if (!msg[index].is_uint())
    throw protocol_error("request ID must be unsigned int");
  return msg[index].as_uint();
}


static void check_size_at_least(size_t msg_len, size_t s)
{
  if (msg_len < s)
    throw protocol_error("json message not enough elements");
}

/* Constructor */
wamp_session::wamp_session(kernel* __kernel,
                           mode conn_mode,
                           std::unique_ptr<tcp_socket> h,
                           state_fn state_cb,
                           server_msg_handler handler,
                           auth_provider auth)
  : m_state( state::init ),
    __logger(__kernel->get_logger()),
    m_kernel(__kernel),
    m_sid(generate_unique_session_id()),
    m_log_prefix(generate_log_prefix(m_sid)),
    m_socket(std::move(h)),
    m_session_mode(conn_mode),
    m_shfut_has_closed(m_has_closed.get_future()),
    m_time_create(time(NULL)),
    m_time_last_msg_recv(time(NULL)),
    m_next_request_id(1),
    m_auth_proivder(std::move(auth)),
    m_server_requires_auth(true), /* assume server requires auth by default */
    m_notify_state_change_fn(std::move(state_cb)),
    m_server_handler(handler)
{
  static_assert(sizeof(m_state)>1, "m_state not large enough");
}



std::shared_ptr<wamp_session> wamp_session::create(kernel* k,
                                                   std::unique_ptr<tcp_socket> sock,
                                                   state_fn state_cb,
                                                   protocol_builder_fn protocol_builder,
                                                   server_msg_handler handler,
                                                   auth_provider auth)
{
  return create_impl(k, mode::server, std::move(sock),
                     state_cb, protocol_builder, handler, auth);
}


std::shared_ptr<wamp_session> wamp_session::create_impl(kernel* k,
                                                        mode conn_mode,
                                                        std::unique_ptr<tcp_socket> sock,
                                                        state_fn state_cb,
                                                        protocol_builder_fn protocol_builder,
                                                        server_msg_handler handler,
                                                        auth_provider auth)
{
  // Create the new wamp_session, and also, create the first shared_ptr to the
  // wamp_session.  Creating the shared_ptr is particularly important, since
  // this initialised the internal shared_ptr inside the wamp_session object
  // (since it inherits from enable_shared_from_this).
  std::shared_ptr<wamp_session> sp(
    new wamp_session(k, conn_mode, std::move(sock), state_cb, handler, auth)
      );

  wamp_session* rawptr = sp.get(); // rawptr, for capture in lambdas

  auto on_msg_cb = [rawptr](json_array msg, json_uint_t msg_type) {
    /* IO thread */
    std::weak_ptr<wamp_session> wp = rawptr->handle();

    /* receive inbound wamp messages that have been decoded by the
     * protocol and queue them for processing on the EV thread */
    auto fn = [wp,msg,msg_type]() mutable
    {
      if (auto sp = wp.lock())
        sp->process_message(msg, msg_type); // TODO: check efficiency here
    };
    rawptr->m_kernel->get_event_loop()->dispatch(std::move(fn));
  };

  auto upgrade_cb = [rawptr](std::unique_ptr<protocol>&new_proto) {
    /* IO thread */
    rawptr->upgrade_protocol(new_proto);
  };

  auto request_timer_cb = [rawptr](std::chrono::milliseconds interval) {
    /* If protocol has requested a timer, register a reoccurring event to make
     * of the protocol's on_timer function. Called during construction of
     * protocol. */
    if (interval.count() > 0)
    {
      std::weak_ptr<wamp_session> wp = rawptr->handle();
      auto fn = [wp,interval]() -> std::chrono::milliseconds {
        if (auto sp = wp.lock())
        {
          sp->m_proto->on_timer();
          return interval;
        }
        return std::chrono::milliseconds(); /* cancel timer */
      };
      rawptr->m_kernel->get_event_loop()->dispatch(interval, std::move(fn));
    }
  };

  auto protocol_closed_fn = [rawptr](std::chrono::milliseconds delay){
    /* IO thread */
    if (delay.count() == 0) {
      std::lock_guard<std::mutex> guard(rawptr->m_state_lock);
      rawptr->drop_connection_impl("protocol_closed", guard, close_event::protocol_closed);
    }
    else {
      std::weak_ptr<wamp_session> wp = rawptr->handle();
      /* implement delay before requesting session closure */
      auto fn = [wp]() mutable -> std::chrono::milliseconds
      {
        if (auto sp = wp.lock()) {
          std::lock_guard<std::mutex> guard(sp->m_state_lock);
          sp->drop_connection_impl("protocol_closed", guard, close_event::protocol_closed);
        }
        return std::chrono::milliseconds(0);
      };
      rawptr->m_kernel->get_event_loop()->dispatch(delay, std::move(fn));
    }
  };

  // Create the protocol, using the builder function passed in. Here we use only
  // the raw pointer, not the shared pointer. If we use the latter (ie if they
  // were captured by the lambdas), the wamp_session would hold references to
  // itself, and so would be tricky to delete.

  sp->m_proto = protocol_builder(sp->m_socket.get(),
                                 std::move(on_msg_cb),
                                 {
                                   std::move(upgrade_cb),
                                   std::move(request_timer_cb),
                                   std::move(protocol_closed_fn)
                                  });

  // Enable the socket for read events; this can only take place once the
  // session's weak self pointer has been set up.
  sp->m_socket->start_read(
    [rawptr](char* s, size_t n){rawptr->io_on_read(s,n);},
    [rawptr](uverr ec){rawptr->io_on_error(ec);}
    );

  // set up a timer to expire this session if it has not been successfully
  // opened within a maximum time duration
  std::weak_ptr<wamp_session> wp = sp;
  k->get_event_loop()->dispatch(
    sp->m_options.max_pending_open,
    [wp]()
    {
      if (auto sp = wp.lock())
      {
        if (sp->is_pending_open())
          sp->drop_connection("wamp.error.logon_timeout");
      }
      return std::chrono::milliseconds(0);
    });

  return sp;
}


/* Destructor */
wamp_session::~wamp_session()
{
  // ANY thread, including IO

  // Note: dont log in here, just in case logger has been deleted.

  // Because it might be the IO thread that is executing this destructor, we
  // take the asynchronous approach to closing and deleting the tcp_socket;
  // i.e. we cannot take the synchronous approach because it is invalid to block
  // on the IO thread.

  if (!m_socket->is_closed())
  {
    if (m_kernel->get_io()->this_thread_is_io())
    {
      m_socket->reset_listener();
      tcp_socket * rawptr = m_socket.get();

      try {
        if ( m_socket->close([rawptr](){
              delete rawptr; // socket deleted on IO thread
            })
          )
        {
          m_socket.release();
        }
      }
      catch (io_loop_closed&) {
        /* ioloop already closed, wait not needed */
      }
    }
    else
    {
      try {
        m_socket->close();
        m_socket->closed_future().wait();
      }
      catch (io_loop_closed&) {
        /* ioloop already closed, wait not needed */
      }
    }
  }
}


void wamp_session::io_on_read(char* src, size_t len)
{
  /* IO thread */

  try
  {
    if (len > 0) {
      m_proto->io_on_read(src,len);
    }
    else  {
      std::lock_guard<std::mutex> guard(m_state_lock);
      drop_connection_impl("sock_eof", guard, close_event::sock_eof);
    }
  }
  catch (...)
  {
    handle_exception();
  }
}


void wamp_session::io_on_error(uverr ec)
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  drop_connection_impl("sock_err", guard, close_event::sock_eof);
}


void wamp_session::update_state_for_outbound(const json_array& msg)
{
  auto message_type = msg[0].as_uint();

  if (session_mode() == mode::server)
  {
    if (message_type == msg_type::wamp_msg_challenge)
    {
      change_state(state::recv_hello, state::sent_challenge);
    }
    else if (message_type == msg_type::wamp_msg_welcome)
    {
      change_state(m_server_requires_auth?state::recv_auth:state::recv_hello, state::open);
    }
    else
    {
      if (!is_open())
      {
        LOG_ERROR(m_log_prefix << "unexpected message sent while session not open: " << msg);
        this->close();
      }
    }
  }
  else
  {
    if (message_type == msg_type::wamp_msg_hello)
    {
      change_state(state::init, state::sent_hello);
    }
    else if (message_type == msg_type::wamp_msg_authenticate)
    {
      change_state(state::recv_challenge, state::sent_auth);
    }
    else
    {
      if (!is_open())
      {
        LOG_ERROR(m_log_prefix << "unexpected message sent while session not open");
        this->close();
      }
    }
  }

}


const char* wamp_session::to_string(wamp_session::state s)
{
  switch (s) {
    case wamp_session::state::init : return "init";
    case wamp_session::state::recv_hello : return "recv_hello";
    case wamp_session::state::sent_challenge : return "sent_challenge";
    case wamp_session::state::recv_auth : return "recv_auth";
    case wamp_session::state::sent_hello : return "sent_hello";
    case wamp_session::state::recv_challenge : return "recv_challenge";
    case wamp_session::state::sent_auth : return "sent_auth";
    case wamp_session::state::open : return "open";
    case wamp_session::state::closing_wait : return "closing_wait";
    case wamp_session::state::closing : return "closing";
    case wamp_session::state::closed : return "closed";
    default: return "unknown";
  };
}


void wamp_session::change_state(state expected, state next)
{
  return change_state(expected, expected, next);
}


void wamp_session::change_state(state expected1, state expected2, state next)
{
  std::lock_guard<std::mutex> guard(m_state_lock);

  if (m_state == state::closed)
    return;

  if (is_in(m_state, expected1, expected2))
  {
    LOG_INFO(m_log_prefix << "state: from " << to_string(m_state) << " to " << to_string(next));
    m_state = next;
  }
  else
  {
    LOG_ERROR(m_log_prefix << "state failure, cannot move from " << to_string(m_state) << " to " << to_string(next) );
    drop_connection_impl(WAMP_ERROR_UNEXPECTED_STATE, guard, close_event::local_request);
  }
}

const char* wamp_session::to_string(close_event v)
{
  switch (v)
  {
    case close_event::local_request   : return "local_request";
    case close_event::recv_abort      : return "recv_abort";
    case close_event::recv_goodbye    : return "recv_goodbye";
    case close_event::sock_eof        : return "sock_eof";
    case close_event::protocol_closed : return "protocol_closed";
  };

  return "unknown";
}

void wamp_session::process_inbound_abort(json_array &)
{
  LOG_WARN(m_log_prefix << "received ABORT from peer, closing session");

  std::lock_guard<std::mutex> guard(m_state_lock);
  drop_connection_impl("received ABORT from peer", guard,
                       close_event::recv_abort);
}


void wamp_session::process_inbound_goodbye(json_array &)
{
  std::lock_guard<std::mutex> guard(m_state_lock);

  drop_connection_impl(WAMP_ERROR_GOODBYE_AND_OUT, guard, close_event::recv_goodbye);
}


void wamp_session::process_message(json_array& ja,
                                   json_uint_t message_type)
{
  /* EV thread */

  /* If session is in closed state, then we shall not allow any furthur
   * callbacks into application code, so we can discard this message. */
  if (is_closed())
    return;

  m_time_last_msg_recv = time(NULL);

  try
  {
    /* session state validation */

    if (message_type == msg_type::wamp_msg_abort)
      return process_inbound_abort(ja);

    if (message_type == msg_type::wamp_msg_goodbye)
      return process_inbound_goodbye( ja );

    if (session_mode() == mode::server)
    {
      if (message_type == msg_type::wamp_msg_hello)
      {
        change_state(state::init, state::recv_hello);
        handle_HELLO(ja);
        return;
      }
      else if (message_type == msg_type::wamp_msg_authenticate)
      {
        change_state(state::sent_challenge, state::recv_auth);
        handle_AUTHENTICATE(ja);
        return;
      }

      switch (message_type)
      {
        case msg_type::wamp_msg_call :
          process_inbound_call(ja);
          return;

        case msg_type::wamp_msg_yield :
          process_inbound_yield(ja);
          return;

        case msg_type::wamp_msg_publish :
          process_inbound_publish(ja);
          return;

        case msg_type::wamp_msg_subscribe :
          process_inbound_subscribe(ja);
          return;

        case msg_type::wamp_msg_unsubscribe :
          process_inbound_unsubscribe(ja);
          return;

        case msg_type::wamp_msg_register :
          process_inbound_register(ja);
          return;

        case msg_type::wamp_msg_error :
          process_inbound_error(ja);
          return;

        case msg_type::wamp_msg_heartbeat: return;

        default:
          std::ostringstream os;
          os << "unknown message type " << (int)message_type;
          throw protocol_error(os.str());
      }
    }
    else
    {
      if (message_type == msg_type::wamp_msg_challenge)
      {
        change_state(state::sent_hello, state::recv_challenge);
        handle_CHALLENGE(ja);
        return;
      }
      else if (message_type == msg_type::wamp_msg_welcome)
      {
        change_state(state::sent_auth, state::sent_hello, state::open);
        if (is_open())
          notify_session_open();
        return;
      }

      switch (message_type)
      {
        case msg_type::wamp_msg_registered :
          process_inbound_registered(ja);
          return;

        case msg_type::wamp_msg_invocation :
          process_inbound_invocation(ja);
          return;

        case msg_type::wamp_msg_subscribed :
          process_inbound_subscribed(ja);
          return;

        case msg_type::wamp_msg_unsubscribed :
          process_inbound_unsubscribed(ja);
          return;

        case msg_type::wamp_msg_event :
          process_inbound_event(ja);
          return;

        case msg_type::wamp_msg_result :
          process_inbound_result(ja);
          return;

        case msg_type::wamp_msg_error :
          process_inbound_error(ja);
          return;

        case msg_type::wamp_msg_heartbeat: return;

        default:
          std::ostringstream os;
          os << "unknown message type " << (int)message_type;
          throw protocol_error(os.str());
      }
    }
  }
  catch (...)
  {
    handle_exception();
  }
}


/** Exception handler for all inbound traffic, i.e., processing raw bytes of a
  * socket and processing inbound messages on the event thread. */
void wamp_session::handle_exception()
{
  try
  {
    throw;
  }
  catch ( handshake_error& e )
  {
    LOG_WARN(m_log_prefix << "handhake error: " << e.what());
    m_socket->reset();
    drop_connection(e.what());
  }
  catch ( auth_error& e )
  {
    LOG_WARN(m_log_prefix << "auth error: " << e.what());
    drop_connection(e.error_uri());
  }
  catch ( protocol_error& e )
  {
    LOG_WARN(m_log_prefix << "protocol error: " << e.what());
    drop_connection(WAMP_ERROR_BAD_PROTOCOL);
  }
  catch (wamp_error & e)
  {
    // We don't expect a wamp_error here; they are intended to be caught inside
    // the relevant process method.
    LOG_WARN(m_log_prefix << "unexpected wamp error: " << e.what());
    drop_connection(e.error_uri());
  }
  catch (std::exception & e)
  {
    LOG_WARN(m_log_prefix << "exception: " << e.what());
    drop_connection(WAMP_RUNTIME_ERROR);
  }
  catch (...)
  {
    LOG_WARN(m_log_prefix << "unknown exception");
    drop_connection(WAMP_RUNTIME_ERROR);
  }
}


void wamp_session::send_msg(const json_array& jv)
{
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if (is_in(m_state, state::closing, state::closed, state::closing_wait))
      return;
  }

  update_state_for_outbound(jv);

  m_proto->send_msg(jv);
}


void wamp_session::handle_HELLO(json_array& ja)
{
  /* EV thread */

  std::string realm = ja.at(1).as_string();
  const json_object & authopts = ja.at(2).as_object();
  std::string authid = json_get_copy(authopts, "authid", "").as_string();

  if (realm.empty())
    throw auth_error(WAMP_ERROR_NO_SUCH_REALM, "empty realm not allowed");

  {
    // update the realm & authid, and protect from multiple assignments to the
    // value, so that it cannot be changed once set
    std::lock_guard<std::mutex> guard(m_realm_lock);
    if (m_realm.empty())
      m_realm  = realm;
    if (m_authid.empty())
      m_authid = authid;
  }

  auth_provider::mode auth_required;
  std::set<std::string> server_auth_methods;
  std::tie(auth_required,server_auth_methods) = m_auth_proivder.policy(authid, realm);

  if (auth_required == auth_provider::mode::open)
  {
    m_server_requires_auth = false;
    send_WELCOME();
    return;
  }
  else if (auth_required != auth_provider::mode::authenticate)
  {
    if (auth_required == auth_provider::mode::forbidden)
      throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                       "auth_provider rejected user for realm");
  }

  /* --- Authentication required --- */

  // initial implementation is basic; we just try to find if "wampcra" is
  // supported by both server and client

  auto client_methods = json_get_copy(authopts, "authmethods",
                                      json_value::make_array()).as_array();
  std::set<std::string> client_unique_methods;

  for (auto & item : client_methods)
    if (item.is_string())
      client_unique_methods.insert(item.as_string());

  std::set<std::string> intersect;
  std::set_intersection(server_auth_methods.begin(),
                        server_auth_methods.end(),
                        client_unique_methods.begin(),
                        client_unique_methods.end(),
                        std::inserter(intersect,intersect.begin()));

  /* Handle case of no supported authentication methods */
  if (intersect.empty())
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "no auth methods available");

  /* For now the only supported method is 'wampcra'. */
  if (intersect.find("wampcra") == intersect.end())
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "wampcra not available for both client and server");

  /* --- Perform wampcra authentication --- */

  json_object challenge;
  challenge["nonce"] = random_ascii_string(30);
  challenge["authprovider"] = m_auth_proivder.provider_name(realm);
  challenge["authid"] = authid;
  challenge["timestamp"] = iso8601_utc_timestamp();
  challenge["authrole"] = "user";
  challenge["authmethod"] = "wampcra";
  challenge["session"] = std::to_string( unique_id() );
  std::string challengestr = json_encode( challenge );

  {
    std::lock_guard<std::mutex> guard(m_realm_lock);
    if (m_challenge.empty())
      m_challenge = challengestr;
    else
      throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                       "challenge already issued");
  }

  json_array msg({
    msg_type::wamp_msg_challenge,
    "wampcra",
    json_object({{"challenge", std::move(challengestr)}})});
  send_msg( msg );
}


void wamp_session::handle_CHALLENGE(json_array& ja)
{
  /* EV thread */

  check_size_at_least(ja.size(), 3);

  if (!ja[1].is_string())
    throw protocol_error("AuthMethod must be string");

  if (!ja[2].is_object())
    throw protocol_error("Extra must be dict");

  const std::string& authmethod = ja[1].as_string();
  if (authmethod != "wampcra")
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "unknown AuthMethod (only wampcra supported)");

  const json_object & extra = ja[2].as_object();
  std::string challmsg = json_get_copy(extra, "challenge", "").as_string();
  if (challmsg == "")
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "challenge not found in Extra");

  /* generate the authentication digest */

  std::string key;
  if (m_client_secret_fn)
    key = m_client_secret_fn();

  char digest[256];
  unsigned int digestlen = sizeof(digest)-1;
  memset(digest, 0, sizeof(digest));

  int err = compute_HMACSHA256(key.c_str(), key.size(),
                               challmsg.c_str(), challmsg.size(),
                               digest, &digestlen,
                               HMACSHA256_Mode::BASE64);

  if (err == 0) {
    json_array msg{msg_type::wamp_msg_authenticate, digest, json_object()};
    send_msg(msg);
  }
  else
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "failed to compute HMAC SHA256 diget");

}


void wamp_session::handle_AUTHENTICATE(json_array& ja)
{
  /* EV thread */

  // the digest generated by the peer
  const std::string & peer_digest = ja[1].as_string();

  std::string orig_challenge;
  {
    std::lock_guard<std::mutex> guard(m_realm_lock);
    orig_challenge = m_challenge;
  }

  bool cra_ok = false;

  if (m_auth_proivder.check_cra) {
    /* Client program has provided the CRA check function, so use that */
    cra_ok = m_auth_proivder.check_cra(m_authid, m_realm, orig_challenge,
                                       peer_digest);
  }
  else
  {
    /* Client program has not provided the CRA check function, so perform the
     * sha/hash ourself */
    std::string key = m_auth_proivder.user_secret(m_authid, m_realm);

    char digest[256];
    unsigned int digestlen = sizeof(digest)-1;
    memset(digest, 0, sizeof(digest));

    int r = compute_HMACSHA256(key.c_str(), key.size(),
                               orig_challenge.c_str(), orig_challenge.size(),
                               digest, &digestlen,
                               HMACSHA256_Mode::BASE64);
    for (size_t i = 0; i < key.size(); i++) key[i]='\0';
    if (r == -1)
      throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                       "HMAC SHA256 failed");

    cra_ok = (digest == peer_digest);
  }

  if (cra_ok)
    send_WELCOME();
  else
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "client failed challenge-response-authentication");
}


void wamp_session::send_WELCOME()
{
  json_object details;
  details["roles"] = json_object( {
      {"broker", json_value::make_object()},
      {"dealer", json_value::make_object()}} );

  json_array msg { msg_type::wamp_msg_welcome,
      m_sid,
      std::move( details )
      };

  send_msg( msg );

  if (is_open())
    notify_session_open();
}


/* Notify any callback of state change to open. This is deliberately performed
 * on the event thread, to prevent IO thread going into user code.
 */
void wamp_session::notify_session_open()
{
  /* EV thread */

  if (m_notify_state_change_fn)
    m_notify_state_change_fn(*this, true /* session is open */);

  m_promise_on_open.set_value();
}


bool wamp_session::is_open() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == state::open;
}

bool wamp_session::is_closed() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state == state::closed;
}

bool wamp_session::is_pending_open() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return (m_state != state::open
          && m_state != state::closed
          && m_state != state::closing
          && m_state != state::closing_wait );
}


std::future<void> wamp_session::hello(client_credentials cc)
{
  /* USER thread */

  {
    std::lock_guard<std::mutex> guard(m_realm_lock);

    if (cc.realm.empty())
      throw std::runtime_error("realm cannot be empty");

    if (!m_realm.empty())
      throw std::runtime_error("hello cannot be called more than once");

    if (m_realm.empty()) m_realm = cc.realm;
  }

  m_client_secret_fn = std::move( cc.secret_fn );

  auto initiate_cb = [this, cc]()
    {
      json_object roles ({
          {"publisher",  json_object()},
          {"subscriber", json_object()},
          {"caller",     json_object()},
          {"callee",     json_object()}
        });

      json_array msg { json_value(msg_type::wamp_msg_hello), json_value(cc.realm) };
      json_object& opt = json_append<json_object>( msg );

      opt[ "roles" ] = std::move( roles );
      opt[ "agent" ] = package_string();
      opt[ "authid"] = std::move(cc.authid);

      json_array& ja = json_insert<json_array>(opt, "authmethods");
      for (auto item : cc.authmethods)
        ja.push_back( std::move(item) );

      send_msg( msg );
    };

  m_proto->initiate(std::move(initiate_cb));

  return m_promise_on_open.get_future();
}


time_t wamp_session::time_last() const
{
  return m_time_last_msg_recv;
}


time_t wamp_session::time_created() const
{
  return m_time_create;
}


const std::string& wamp_session::realm() const
{
  // need this lock, because realm might be updated from IO thread during logon
  std::lock_guard<std::mutex> guard(m_realm_lock);
  return m_realm;
}


t_request_id wamp_session::provide(std::string uri,
                                   const json_object& options,
                                   on_registered_fn registered_cb,
                                   on_invocation_fn invocation_cb,
                                   void * user)
{
  json_array msg {
    msg_type::wamp_msg_register,
    0,
    options,
    uri };

  procedure p {
    uri,
    std::move(registered_cb),
    std::move(invocation_cb),
    user };

  t_request_id request_id;
  {
    std::lock_guard<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::lock_guard<std::mutex> guard(m_pending_lock);
      m_pending_register[request_id] = p;
    }

    send_msg( msg );
  }

  LOG_INFO(m_log_prefix << "sending register request for '" << uri << "', request_id " << request_id);
  return request_id;
}

void wamp_session::process_inbound_registered(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id  = extract_request_id(msg, 1);

  if (!msg[2].is_uint())
    throw protocol_error("registration ID must be unsigned int");

  t_registration_id registration_id = msg[2].as_uint();

  on_registered_fn on_result;
  registered_info info { request_id, registration_id, false, "", nullptr};
  {
    std::lock_guard<std::mutex> guard(m_pending_lock);

    auto iter = m_pending_register.find( request_id );
    if (iter == m_pending_register.end())
      return;

    on_result = std::move(iter->second.registered_cb);
    iter->second.registered_cb = nullptr; /* ensure callback object is invalid*/

    info.user = iter->second.user;

    m_procedures[registration_id] = std::move(iter->second);
    m_pending_register.erase(iter);
  }

  if (on_result && user_cb_allowed()) {
    try {
      on_result(*this, info);
    }
    catch (...) { /* ignore */ }
  }

  LOG_INFO(m_log_prefix << "procedure '"<< m_procedures[registration_id].uri <<"' registered"
           << " with registration_id " << registration_id);
}


void wamp_session::process_inbound_invocation(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_uint())
    throw protocol_error("registration ID must be unsigned int");
  t_registration_id registration_id = msg[2].as_uint();

  if (!msg[3].is_object())
    throw protocol_error("details must be json object");
  json_object &  details = msg[3].as_object();

  // find the procedure
  try
  {
    auto iter = m_procedures.find(registration_id);

    if (iter == m_procedures.end())
      throw wamp_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION);

    std::string uri = iter->second.uri;

    wamp_args args;
    if ( msg.size() > 4 )
      args.args_list = std::move(msg[4].as_array());
    if ( msg.size() > 5 )
      args.args_dict = std::move(msg[5].as_object());

    invocation_info info(request_id,
                         registration_id,
                         std::move(details),
                         std::move(args),
                         iter->second.user);

    if (user_cb_allowed())
      iter->second.invocation_cb(*this, info);
  }
  catch (wampcc::wamp_error& ex)
  {
    reply_with_error(msg_type::wamp_msg_invocation, request_id, ex.args(), ex.error_uri());
  }
}


t_request_id wamp_session::subscribe(std::string uri,
                                     json_object options,
                                     on_subscribed_fn req_cb,
                                     on_event_fn event_cb,
                                     void * user)
{
  json_array msg {msg_type::wamp_msg_subscribe, 0, options, uri};
  subscribe_request sub {uri, std::move(req_cb), std::move(event_cb), user};

  t_request_id request_id;
  {
    std::lock_guard<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::lock_guard<std::mutex> guard(m_pending_lock);
      m_pending_subscribe[request_id] = std::move(sub);
    }
    send_msg( msg );
  }

  LOG_INFO(m_log_prefix << "sending subscribe for '" << uri << "', request_id " << request_id);
  return request_id;
}


t_request_id wamp_session::unsubscribe(t_subscription_id subscription_id,
                                       on_unsubscribed_fn user_cb,
                                       void * user)
{
  json_array msg {msg_type::wamp_msg_unsubscribe, 0, subscription_id};

  unsubscribe_request req {std::move(user_cb), subscription_id, user};

  t_request_id request_id;
  {
    std::lock_guard<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::lock_guard<std::mutex> guard(m_pending_lock);
      m_pending_unsubscribe[request_id] = std::move(req);
    }
    send_msg( msg );
  }

  LOG_INFO("sending unsubscribe for subscription_id " << subscription_id
           << ", request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_subscribed(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_uint())
      throw protocol_error("subscription ID must be unsigned int");
  t_subscription_id subscription_id = msg[2].as_uint();

  // reduce locking scope
  subscribe_request temp;
  {
    std::lock_guard<std::mutex> guard(m_pending_lock);
    auto iter = m_pending_subscribe.find( request_id );

    if (iter != m_pending_subscribe.end())
    {
      temp = std::move(iter->second);
      m_pending_subscribe.erase(iter);
    }
    else
    {
      LOG_WARN("no pending subscribe for subscribed response with request_id "
               << request_id);
      return;
    }
  }

  LOG_INFO("subscribed to topic '"<< temp.uri <<"'"
           << " with subscription_id " << subscription_id);

  auto iter = m_subscriptions.find(subscription_id);
  if (iter != m_subscriptions.end())
  {
    /* This is permitted by WAMP specification, ie multiple subscriptions to a
     * topic.  However for such situations, each identical subscription will use
     * the same subscription ID and only be published once.  Given this is
     * unusal behaviour we raise a warning.  We also use the request callback in
     * replace of the previous callback. */
    LOG_WARN("multiple subscriptions made to topic '"<< temp.uri <<"'");
    iter->second.event_cb  = std::move(temp.event_cb);
    iter->second.user = temp.user;
  }
  else
  {
    subscription sub { std::move(temp.event_cb), temp.user };
    m_subscriptions.insert({subscription_id, std::move(sub)});
  }

  // invoke user callback if permitted, and handle exception
  if (temp.request_cb && user_cb_allowed())
    try {
      subscribed_info info {request_id, subscription_id, false, {}, temp.user};
      temp.request_cb(*this, info);
    }
    catch(...) {
      log_exception(__logger, "inbound subscribed user callback");
    }
}


void wamp_session::process_inbound_unsubscribed(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 2);

  t_request_id request_id = extract_request_id(msg, 1);

  unsubscribe_request orig_req;
  {
    std::lock_guard<std::mutex> guard(m_pending_lock);
    auto iter = m_pending_unsubscribe.find(request_id);

    if (iter != m_pending_unsubscribe.end())
    {
      orig_req = std::move(iter->second);
      m_pending_unsubscribe.erase(iter);
    }
    else
    {
      LOG_WARN("no pending unsubscribe for unsubscribed response with request_id "
               << request_id);
      return;
    }
  }

  m_subscriptions.erase(orig_req.subscription_id);

  LOG_INFO("unsubscribed, subscription_id " << orig_req.subscription_id
           << ", request_id " << request_id);

  // invoke user callback if permitted, and handle exception
  if (orig_req.user_cb && user_cb_allowed())
    try {
      orig_req.user_cb(*this, {request_id, true, {}, orig_req.user});
    }
    catch(...) {
      log_exception(__logger, "inbound unsubscribed user callback");
    }
}


void wamp_session::process_inbound_event(json_array & msg)
{
  /* EV thread */

  t_subscription_id subscription_id = msg[1].as_uint();
  json_object details = std::move(msg.at(3).as_object());
  json_value * ptr_args_list = json_get_ptr(msg, 4); // optional
  json_value * ptr_args_dict = json_get_ptr(msg, 5); // optional

  const json_array  & args_list = ptr_args_list? ptr_args_list->as_array()  : json_array();
  const json_object & args_dict = ptr_args_dict? ptr_args_dict->as_object() : json_object();

  auto iter = m_subscriptions.find(subscription_id);
  if (iter !=m_subscriptions.end())
  {
    try {
      if (user_cb_allowed())
      {
        event_info ev { subscription_id,
            std::move( details ),
            { args_list, args_dict },
            iter->second.user
              };
        iter->second.event_cb(*this, ev);
      }
    } catch (...){ log_exception(__logger, "inbound event user callback"); }

  }
  else
  {
    LOG_WARN("Topic event ignored because subscription_id "
           << subscription_id << " not found");
  }
}


/* Initiate an outbound call sequence */
t_request_id wamp_session::call(std::string uri,
                                const json_object& options,
                                wamp_args args,
                                on_result_fn user_cb,
                                void* user)
{
  /* USER thread */

  json_array msg {msg_type::wamp_msg_call, 0, options, uri, args.args_list, args.args_dict};

  wamp_call mycall { uri, std::move(user_cb), user };

  t_request_id request_id;
  {
    std::lock_guard<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::lock_guard<std::mutex> guard(m_pending_lock);
      m_pending_call[request_id] = std::move(mycall);
    }

    send_msg( msg );
  }

  LOG_INFO("sending call request for '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_result(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id  = extract_request_id(msg, 1);

  if (!msg[2].is_object())
      throw protocol_error("details must be json object");
  json_object & options = msg[2].as_object();

  wamp_call orig_call;

  {
    std::lock_guard<std::mutex> guard(m_pending_lock);
    auto iter = m_pending_call.find( request_id );
    if (iter != m_pending_call.end())
    {
      orig_call = std::move(iter->second);
      m_pending_call.erase(iter);
    }
    else
    {
      LOG_WARN("ignoring result for unknown call, request_id " << request_id);
    }
  }

  if (orig_call.user_cb && user_cb_allowed())
  {
    result_info r;
    r.was_error = false;
    r.user = orig_call.user;
    if (msg.size()>3) r.args.args_list = std::move(msg[3].as_array());
    if (msg.size()>4) r.args.args_dict = std::move(msg[4].as_object());
    r.additional = options;

    try {
      orig_call.user_cb(*this, std::move(r));
    }
    catch(...) {
      log_exception(__logger, "inbound result user callback");
    }
  }
}

/* Handles errors for both active & passive sessions */
void wamp_session::process_inbound_error(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 5);

  auto orig_request_type = msg[1].as_int();
  t_request_id request_id = extract_request_id(msg, 2);
  json_object & details = msg[3].as_object();
  std::string& error_uri = msg[4].as_string();

  if (session_mode() == mode::server)
  {
    switch (orig_request_type)
    {
      case msg_type::wamp_msg_invocation:
      {
        wamp_invocation orig_request;

        {
          std::lock_guard<std::mutex> guard(m_pending_lock);
          auto iter = m_pending_invocation.find( request_id );
          if (iter != m_pending_invocation.end())
          {
            orig_request = std::move(iter->second);
            m_pending_invocation.erase(iter);
          }
        }

        wamp_args args;
        if ( msg.size() > 5 ) args.args_list = std::move(msg[5].as_array());
        if ( msg.size() > 6 ) args.args_dict = std::move(msg[6].as_object());
        std::unique_ptr<std::string> error_ptr( new std::string(error_uri) );

        try
        {
          yield_info respone {request_id, details, error_uri, args, orig_request.user };
          orig_request.reply_fn(*this, respone);
        } catch (...) {
          log_exception(__logger, "inbound invocation error user callback");
        }

        break;
      }
      default:
        LOG_WARN("wamp error response has unexpected original request type " << orig_request_type);
        break;
    }
  }
  else
  {
    /* client-mode session */
    switch (orig_request_type)
    {
      case msg_type::wamp_msg_call :
      {
        wamp_call orig_call;
        bool found = false;

        {
          std::lock_guard<std::mutex> guard(m_pending_lock);
          auto iter = m_pending_call.find( request_id );
          if (iter != m_pending_call.end())
          {
            found = true;
            orig_call = std::move(iter->second);
            m_pending_call.erase(iter);
          }
        }

        if (found)
        {
          if (orig_call.user_cb && user_cb_allowed())
          {
            result_info r;
            r.was_error = true;
            r.error_uri = error_uri;
            r.user = orig_call.user;
            if ( msg.size() > 5 ) r.args.args_list = msg[5].as_array();
            if ( msg.size() > 6 ) r.args.args_dict = msg[6].as_object();
            r.additional = details;

            try {
              orig_call.user_cb(*this, std::move(r));
            }
            catch(...){ log_exception(__logger, "inbound call error user callback");}
          }
        }
        else
        {
          LOG_WARN("no pending call for error response with request_id "
                   << request_id);
        }
        break;
      }
      case msg_type::wamp_msg_subscribe :
      {
        /* dont hold any locks when calling the user */
        subscribe_request orig_request;
        {
          std::lock_guard<std::mutex> guard(m_pending_lock);
          auto iter = m_pending_subscribe.find( request_id );
          if (iter != m_pending_subscribe.end())
          {
            orig_request = std::move(iter->second);
            m_pending_subscribe.erase(iter);
          }
          else
          {
            /* TODO: dont log inside the critical section. */
            LOG_WARN("no pending subscribe for error response with request_id "
                     << request_id);
            break;
          }
        }

        // invoke user callback if permitted, and handle exception
        if (orig_request.request_cb && user_cb_allowed())
          try {
            subscribed_info info {request_id, 0, true, std::move(error_uri), orig_request.user};
            orig_request.request_cb(*this, info);
          }
          catch(...) {
            log_exception(__logger, "inbound subscribed user callback");
          }

        break;
      };
      case msg_type::wamp_msg_unsubscribe :
      {
        /* dont hold any locks when calling the user */
        unsubscribe_request orig_request;
        {
          std::lock_guard<std::mutex> guard(m_pending_lock);
          auto iter = m_pending_unsubscribe.find(request_id);
          if (iter != m_pending_unsubscribe.end())
          {
            orig_request = std::move(iter->second);
            m_pending_unsubscribe.erase(iter);
          }
          else
          {
            LOG_WARN("no pending unsubscribe for error response with request_id "
                     << request_id);
            break;
          }
        }

        // invoke user callback if permitted, and handle exception
        if (orig_request.user_cb && user_cb_allowed())
          try {
            orig_request.user_cb(*this, {request_id, false, std::move(error_uri), orig_request.user});
          }
          catch(...) {
            log_exception(__logger, "inbound unsubscribed user callback");
          }

        break;
      };
      case msg_type::wamp_msg_register:
      {
        /* attempt to register a procedure has failed, if we can, notify the
         * application of this failure */

        procedure orig;

        {
          std::lock_guard<std::mutex> guard(m_pending_lock);
          auto iter = m_pending_register.find(request_id);
          if (iter == m_pending_register.end())
            return;
          orig = std::move(iter->second);
          m_pending_register.erase(iter);
        }

        if (orig.registered_cb && user_cb_allowed()) {
          try {
            registered_info info;
            info.request_id = request_id;
            info.registration_id = 0;
            info.was_error = true;
            info.error_uri = error_uri;
            info.user = orig.user;
            orig.registered_cb(*this, std::move(info));
          }
          catch(...) {
            log_exception(__logger, "inbound register on_result callback");
          }
        }
        break;
      }
      default:
        LOG_WARN("wamp error response has unexpected original request type " << orig_request_type);
        break;
    }
  }
}


t_request_id wamp_session::publish(std::string uri,
                                   const json_object& options,
                                   wamp_args args)
{
  /* USER thread */

  json_array msg {msg_type::wamp_msg_publish, 0, options, uri, args.args_list, args.args_dict};

  t_request_id request_id;

  {
    std::lock_guard<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    send_msg( msg );
  }

  return request_id;
}


void wamp_session::process_inbound_call(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[3].is_string()) throw protocol_error("procedure uri must be string");
  std::string procedure_uri = std::move(msg[3].as_string());

  wamp_args my_wamp_args;
  if ( msg.size() > 4 )
    my_wamp_args.args_list = msg[4].as_array();
  if ( msg.size() > 5 )
    my_wamp_args.args_dict = msg[5].as_object();

  session_handle wp = this->handle();
  auto reply_fn = [wp, request_id](wamp_args args,
                                   std::unique_ptr<std::string> error_uri)
    {
      /* EV thread */

      // m_pending.erase(request_id);   <---- if that is found, ie, erase the function that allows for cancel
      // send a RESULT back to originator of the call

      if (auto sp = wp.lock())
      {
        if (!error_uri)
        {
          json_array msg {msg_type::wamp_msg_result, request_id, json_object(), args.args_list, args.args_dict};
          sp->send_msg(msg);
        }
        else
        {
          json_array msg {msg_type::wamp_msg_error, msg_type::wamp_msg_call, request_id, json_object(), *error_uri,
                          args.args_list, args.args_dict};
          sp->send_msg(msg);
        }
      }
    };

  try
  {
    json_object options;
    m_server_handler.on_call(*this,
                             request_id,
                             procedure_uri,
                             options,
                             my_wamp_args);
  }
  catch(wamp_error& ex)
  {
    reply_with_error(msg_type::wamp_msg_call, request_id, ex.args(), ex.error_uri());
  }
}


/* perform outbound invocation request */
t_request_id wamp_session::invocation(t_registration_id registration_id,
                                      const json_object& options,
                                      wamp_args args,
                                      on_yield_fn fn,
                                      void * user)
{
  /* EV & USER thread */

  json_array msg {msg_type::wamp_msg_invocation, 0, registration_id, options,
      args.args_list, args.args_dict};

  t_request_id request_id;
  wamp_invocation my_invocation {std::move(fn), user};

  {
    std::lock_guard<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::lock_guard<std::mutex> guard(m_pending_lock);
      m_pending_invocation[request_id] = std::move(my_invocation);
    }

    send_msg( msg );
  }

  return  request_id;
}


void wamp_session::process_inbound_yield(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  json_object & options = msg[2].as_object();

  wamp_args args;
  if ( msg.size() > 3 )
    args.args_list = msg[3].as_array();
  if ( msg.size() > 4 )
    args.args_dict = msg[4].as_object();

  auto iter = m_pending_invocation.find(request_id);
  if (iter != m_pending_invocation.end())
  {
    if (iter->second.reply_fn)
    {
      try {
        yield_info info (request_id, options, args, iter->second.user);
        iter->second.reply_fn(*this, info);
      } catch (...){}
    }
    m_pending_invocation.erase(iter);
  }

}


void wamp_session::process_inbound_publish(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_object())
    throw protocol_error("options must be json object");

  if (!msg[3].is_string()) throw protocol_error("topic uri must be string");

  wamp_args args;
  if ( msg.size() > 4 )
    args.args_list = std::move(msg[4].as_array());
  if ( msg.size() > 5 )
    args.args_dict = std::move(msg[5].as_object());

  try
  {
    m_server_handler.on_publish(*this, std::move(msg[3].as_string()), std::move(msg[2].as_object()), args);
  }
  catch(wamp_error& ex)
  {
    reply_with_error(msg_type::wamp_msg_publish, request_id, ex.args(), ex.error_uri());
  }
}


void wamp_session::process_inbound_subscribe(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_object()) throw protocol_error("options must be json object");
  if (!msg[3].is_string()) throw protocol_error("topic uri must be string");

  std::string topic_uri = std::move(msg[3].as_string());

  try
  {
    m_server_handler.on_subscribe(*this, request_id, topic_uri, msg[2].as_object());
  }
  catch(wamp_error& ex)
  {
    reply_with_error(msg_type::wamp_msg_subscribe, request_id, ex.args(), ex.error_uri());
  }
}

void wamp_session::process_inbound_unsubscribe(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_uint()) throw protocol_error("subscription id must be uint");
  t_subscription_id sub_id = msg[2].as_uint();

  try
  {
    m_server_handler.on_unsubscribe(*this, request_id, sub_id);
  }
  catch(wamp_error& ex)
  {
    reply_with_error(msg_type::wamp_msg_unsubscribe, request_id, ex.args(), ex.error_uri());
  }
}

void wamp_session::process_inbound_register(json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_object())
      throw protocol_error("options must be json object");
  json_object & options = msg[2].as_object();

  if (!msg[3].is_string())
    throw protocol_error("procedure uri must be string");
  std::string & uri = msg[3].as_string();

  try
  {
    m_server_handler.on_register(*this,
                                 request_id,
                                 options,
                                 uri);
  }
  catch(wamp_error& ex)
  {
    reply_with_error(msg_type::wamp_msg_register, request_id, ex.args(), ex.error_uri());
  }
}

void wamp_session::reply_with_error(
  msg_type request_type,
  t_request_id request_id,
  wamp_args args,
  std::string error_uri)
{
  json_array msg {msg_type::wamp_msg_error, request_type, request_id, json_object(),
      error_uri, args.args_list, args.args_dict};
  send_msg(msg);
}


json_array wamp_session::build_goodbye_message(std::string reason)
{
  return json_array ({msg_type::wamp_msg_goodbye, json_object(), std::move(reason)} );
}


json_array wamp_session::build_abort_message(std::string reason)
{
  return json_array({msg_type::wamp_msg_abort, json_object(), std::move(reason)} );
}


void wamp_session::upgrade_protocol(std::unique_ptr<protocol>& new_proto)
{
  m_proto.swap(new_proto);
}


std::shared_future<void> wamp_session::close()
{
  drop_connection(WAMP_ERROR_CLOSE_REALM);
  return m_shfut_has_closed;
}


void wamp_session::drop_connection(std::string reason)
{
  /* ANY thread */

  std::lock_guard<std::mutex> guard(m_state_lock);
  drop_connection_impl(reason, guard, close_event::local_request);
}


void wamp_session::fast_close()
{
  /* ANY thread */

  if (m_kernel->get_event_loop()->this_thread_is_ev())
  {
    if (is_closed())
      return;

    LOG_INFO(m_log_prefix << "closing");

    try { m_socket->close(); } catch (...){};

    transition_to_closed();
  }
  else
  {
    {
      std::lock_guard<std::mutex> guard(m_state_lock);
      if (m_state == state::closed)
        return;
      terminate(guard);
    }
    m_shfut_has_closed.wait();
  }
}


/* Implement the actual state transition to closed. This must only be called via
 * the EV thread. */
void wamp_session::transition_to_closed()
{
  /* EV thread */

  assert(m_kernel->get_event_loop()->this_thread_is_ev() == true);

  // Make final check of session state to ensure that user callback is only ever
  // called once. Even though this is also protected when the event is initially
  // dispatched, later code modification might attempt to push additional close
  // callbacks.
  {
    std::lock_guard<std::mutex> guard(m_state_lock);
    if (m_state == state::closed)
      return;
    else
      m_state = state::closed;
  }

  // The order of invoking the user callback and setting the has-closed promise
  // is deliberately chosen here.  The promise 'set_value' must be the later
  // action, so that user can rely on it to indicate when all wamp_session
  // callbacks into user code have been complete. But it also implies that
  // during the user callback, the has-closed future cannot be waited on; that
  // would be a programming error.

  try {
    m_notify_state_change_fn(*this, false);
  }
  catch (...) {
    /* ignore */
  }

  m_has_closed.set_value();
}


void wamp_session::schedule_terminate_on_timeout(std::chrono::milliseconds ms,
                                                 bool include_warning)
{
  /* Schedule a timeout so that if graceful closure has not been achieved within
   * a reasonable period then we forcefully terminate the session. */
  std::weak_ptr<wamp_session> wp = shared_from_this();

  event_loop::timer_fn fn = [wp, include_warning]()
    {
      if (auto sp = wp.lock()) {
        std::lock_guard<std::mutex> guard(sp->m_state_lock);
        if (sp->m_state == state::closing_wait) {
          if (include_warning) {
            logger & __logger = sp->__logger;
            LOG_WARN(sp->m_log_prefix << "timeout waiting for peer");
          }
          sp->terminate(guard);
        }
      }
      return std::chrono::milliseconds(0);
    };

  m_kernel->get_event_loop()->dispatch(ms, std::move(fn));
}


void wamp_session::drop_connection_impl(std::string reason,
                                        std::lock_guard<std::mutex>& guard,
                                        close_event event)
{
  /* ANY thread (inc. EV & IO) */


  // Note, we don't check for closing_wait here.  Closing wait is really
  // part of the open stage.
  if (is_in(m_state, state::closed, state::closing))
    return;

  /* If we are dropping the connection as a result of a socket eof, then nothing
   * else to do other than initiate session close. */
  if (event == close_event::sock_eof)
    return terminate(guard);

  auto const cur_state = m_state;

  if (session_mode() == mode::server)
  {
    /* Server-side closure management. */

    if (cur_state == state::closing_wait)
      return;

    if (event == close_event::protocol_closed)
    {
      // Wire protocol has closed.  Fall through to schedule a timeout.
    }
    else if (event != close_event::recv_abort)
    {
      try
      {
        if (cur_state == state::open)
          m_proto->send_msg(build_goodbye_message(reason));
        else
          m_proto->send_msg(build_abort_message(reason));
      }
      catch (...) {}
    }

    m_state = state::closing_wait;
    schedule_terminate_on_timeout(close_timeout, false);
  }
  else
  {
    /* Client-side closure management.  Attempt graceful closure, with timeout
     * if peer does not cooperate. Also make effort to be first to initiate
     * socket close. */

    if (event == close_event::local_request)
    {
      /* Set up a timer to force closure if graceful closure isn't
       * successful. */
      m_state = state::closing_wait;
      schedule_terminate_on_timeout(close_timeout, true);

      if (cur_state == state::open)
         m_proto->send_msg(build_goodbye_message(reason));
       else
         m_proto->send_msg(build_abort_message(reason));

      return;
    }

    if (event == close_event::protocol_closed)
    {
      // Rather than immediately calling terminate, introduce a very brief delay
      // in order to allow any recent & final socket write to complete
      // (e.g. websocket close frame)
      m_state = state::closing_wait;
      schedule_terminate_on_timeout(std::chrono::milliseconds(10), false);
      return;
    }

    if (event == close_event::recv_goodbye)
    {
      if (cur_state == state::open)
        try {
          m_proto->send_msg(build_goodbye_message(reason));
        } catch (...) { }
    }

    schedule_terminate_on_timeout(close_timeout, true);

    /* Attempt graceful shutdown */
    bool handshake_pending = m_proto->initiate_close();
    if (!handshake_pending)
      terminate(guard);
  }
}


/* Initiate the session termination, including socket closure. The state mutex
 * must be provided as an argument.  This method checks existing state, and if
 * not closed, request actual closure on the event thread. */
void wamp_session::terminate(std::lock_guard<std::mutex>&)
{
  /* ANY thread */

  if (is_in(m_state, state::closing, state::closed))
    return;

  m_state = state::closing;
  LOG_INFO(m_log_prefix << "closing");

  try { m_socket->close(); } catch (...){};

  // TODO: what if the EV thread is closed? Have the EV to throw an exception to
  // detect this.
  std::shared_ptr<wamp_session> sp = shared_from_this();
  m_kernel->get_event_loop()->dispatch([sp](){ sp->transition_to_closed(); });
}


bool wamp_session::user_cb_allowed() const
{
  std::lock_guard<std::mutex> guard(m_state_lock);
  return m_state != state::closed;
}


/* Used for test purposes */
void wamp_session::proto_close()
{
  m_proto->initiate_close();
}

void wamp_session::result(t_request_id id)
{
  send_msg({msg_type::wamp_msg_result, id, json_object()});
}

void wamp_session::result(t_request_id id, json_array ja)
{
  send_msg({msg_type::wamp_msg_result, id, json_object(), std::move(ja)});
}

void wamp_session::result(t_request_id id, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_result, id, json_object(), std::move(ja), std::move(jo)});
}

void wamp_session::result(t_request_id id, json_object dt)
{
  send_msg({msg_type::wamp_msg_result, id, std::move(dt)});
}

void wamp_session::result(t_request_id id, json_object dt, json_array ja)
{
  send_msg({msg_type::wamp_msg_result, id, std::move(dt), std::move(ja)});
}

void wamp_session::result(t_request_id id, json_object dt, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_result, id, std::move(dt), std::move(ja), std::move(jo)});
}

void wamp_session::call_error(t_request_id id, std::string uri)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_call, id, json_value::make_object(), std::move(uri)});
}

void wamp_session::call_error(t_request_id id, std::string uri, json_array ja)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_call, id, json_value::make_object(), std::move(uri), std::move(ja)});
}

void wamp_session::call_error(t_request_id id, std::string uri, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_call, id, json_value::make_object(), std::move(uri), std::move(ja), std::move(jo)});
}

void wamp_session::call_error(t_request_id id, std::string uri, json_object details)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_call, id, std::move(details), std::move(uri)});
}

void wamp_session::call_error(t_request_id id, std::string uri, json_object details, json_array ja)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_call, id, std::move(details), std::move(uri), std::move(ja)});
}

void wamp_session::call_error(t_request_id id, std::string uri, json_object details, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_call, id, std::move(details), std::move(uri), std::move(ja), std::move(jo)});
}

void wamp_session::yield(t_request_id id)
{
  send_msg({msg_type::wamp_msg_yield, id, json_value::make_object()});
}

void wamp_session::yield(t_request_id id, json_array ja)
{
  send_msg({msg_type::wamp_msg_yield, id, json_value::make_object(), std::move(ja)});
}

void wamp_session::yield(t_request_id id, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_yield, id, json_value::make_object(), std::move(ja), std::move(jo)});
}

void wamp_session::yield(t_request_id id, json_object opts)
{
  send_msg({msg_type::wamp_msg_yield, id, std::move(opts)});
}

void wamp_session::yield(t_request_id id, json_object opts, json_array ja)
{
  send_msg({msg_type::wamp_msg_yield, id, std::move(opts), std::move(ja)});
}

void wamp_session::yield(t_request_id id, json_object opts, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_yield, id, std::move(opts), std::move(ja), std::move(jo)});
}

void wamp_session::invocation_error(t_request_id id, std::string uri)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_invocation, id,
        json_value::make_object(), std::move(uri)});
}

void wamp_session::invocation_error(t_request_id id,
                                    std::string uri, json_array ja)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_invocation, id,
        json_value::make_object(), std::move(uri), std::move(ja)});
}

void wamp_session::invocation_error(t_request_id id,
                                    std::string uri, json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_invocation, id,
        json_value::make_object(), std::move(uri), std::move(ja), std::move(jo)});
}

void wamp_session::invocation_error(t_request_id id, std::string uri, json_object details)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_invocation, id,
        std::move(details), std::move(uri)});
}

void wamp_session::invocation_error(t_request_id id, std::string uri, json_object details,
                                    json_array ja)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_invocation, id,
        std::move(details), std::move(uri), std::move(ja)});
}

void wamp_session::invocation_error(t_request_id id, std::string uri, json_object details,
                                    json_array ja, json_object jo)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_invocation, id,
        std::move(details), std::move(uri), std::move(ja), std::move(jo)});
}

void wamp_session::subscribed(t_request_id id, t_subscription_id subscription_id)
{
  send_msg({msg_type::wamp_msg_subscribed, id, subscription_id});
}

void wamp_session::subscribe_error(t_request_id id, std::string uri)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_subscribe,
        id, json_value::make_object(), std::move(uri)});
}

void wamp_session::subscribe_error(t_request_id id, std::string uri, json_object details)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_subscribe,
        id, std::move(details), std::move(uri)});
}

void wamp_session::registered(t_request_id id, t_registration_id reg_id)
{
  send_msg({ msg_type::wamp_msg_registered, id, reg_id});
}

void wamp_session::register_error(t_request_id id, std::string uri)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_register,
        id, json_value::make_object(), std::move(uri)});
}

void wamp_session::register_error(t_request_id id, std::string uri, json_object details)
{
  send_msg({msg_type::wamp_msg_error,
        msg_type::wamp_msg_register,
        id,
        std::move(details),
        std::move(uri)});
}

void wamp_session::unsubscribed(t_request_id id)
{
  send_msg({msg_type::wamp_msg_unsubscribed, id});
}

void wamp_session::unsubscribe_error(t_request_id id, std::string uri)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_unsubscribe,
        id, json_value::make_object(), std::move(uri)});
}

void wamp_session::unsubscribe_error(t_request_id id, std::string uri, json_object details)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_unsubscribe,
        id, std::move(details), std::move(uri)});
}

void wamp_session::published(t_request_id id, t_publication_id pub_id)
{
  send_msg({msg_type::wamp_msg_published, id, pub_id});
}

void wamp_session::publish_error(t_request_id id, std::string uri)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_publish,
        id, json_value::make_object(), std::move(uri)});
}

void wamp_session::publish_error(t_request_id id, std::string uri, json_object details)
{
  send_msg({msg_type::wamp_msg_error, msg_type::wamp_msg_publish,
        id, std::move(details), std::move(uri)});
}

void wamp_session::event(t_subscription_id sub_id, t_publication_id pub_id, json_object details, wamp_args args)
{
  json_array msg {msg_type::wamp_msg_event, sub_id, pub_id,
      std::move(details),
      std::move(args.args_list),
      std::move(args.args_dict)};

  send_msg( std::move(msg) );
}

} // namespace wampcc
