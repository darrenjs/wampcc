#include "XXX/wamp_session.h"

#include "XXX/tcp_socket.h"
#include "XXX/protocol.h"
#include "XXX/rpc_man.h"
#include "XXX/event_loop.h"
#include "XXX/log_macros.h"
#include "XXX/utils.h"
#include "XXX/kernel.h"
#include "XXX/rawsocket_protocol.h"

#include <jalson/jalson.h>

#include <memory>
#include <iomanip>
#include <iostream>

#include <string.h>
#include <unistd.h>


#define MAX_PENDING_OPEN_MS 5000
#define MAX_HEARTBEATS_MISSED 3

namespace XXX {

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


static std::atomic<uint64_t> m_next_id(1); // start at 1, so that 0 implies invalid ID
static uint64_t generate_unique_session_id()
{
  return m_next_id++;
}


static t_request_id extract_request_id(jalson::json_array & msg, int index)
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
                           std::unique_ptr<tcp_socket> h,
                           session_state_fn state_cb,
                           protocol_builder_fn protocol_builder,
                           server_msg_handler handler,
                           auth_provider auth)
  : m_state( eInit ),
    __logger(__kernel->get_logger()),
    m_kernel(__kernel),
    m_sid( generate_unique_session_id() ),
    m_socket(std::move(h)),
    m_shfut_has_closed(m_has_closed.get_future()),
    m_hb_intvl(m_kernel->get_config().use_wamp_heartbeats?60:0),
    m_time_create(time(NULL)),
    m_time_last_msg_recv(time(NULL)),
    m_next_request_id(1),
    m_auth_proivder(std::move(auth)),
    m_notify_state_change_fn(state_cb),
    m_server_handler(handler),
    m_proto(
      protocol_builder(
        m_socket.get(),
        [this](jalson::json_array msg, int msg_type)
        {
          /* process on the EV thread */
          std::weak_ptr<wamp_session> wp = handle();
          std::function<void()> fn = [wp,msg,msg_type]() mutable
            {
              if (auto sp = wp.lock())
                sp->process_message(msg_type, msg);
            };
          m_kernel->get_event_loop()->dispatch(std::move(fn));
        }
        ))
{
  std::cout << "wamp_session created\n";
}


std::shared_ptr<wamp_session> wamp_session::create(kernel* k,
                                                   std::unique_ptr<tcp_socket> ioh,
                                                   session_state_fn state_cb,
                                                   protocol_builder_fn protocol_builder,
                                                   server_msg_handler handler,
                                                   auth_provider auth)
{
  std::shared_ptr<wamp_session> sp(
    new wamp_session(k, std::move(ioh), state_cb, protocol_builder, handler, auth)
      );

  sp->m_self_weak = sp;

  // can't put this initialisation step inside wamp_sesssion constructor,
  // because the shared pointer wont be created & available inside the
  // constructor
  sp->m_socket->start_read( sp.get() );

  // set up a timer to expire this session if it has not been successfully
  // opened within a maximum time duration
  std::weak_ptr<wamp_session> wp = sp;
  k->get_event_loop()->dispatch(
    std::chrono::milliseconds(MAX_PENDING_OPEN_MS),
    [wp]()
    {
      if (auto sp = wp.lock())
      {
        if (sp->is_pending_open())
          sp->drop_connection("wamp.error.logon_timeout");
      }
      return 0;
    });

  return sp;
}


/* Destructor */
wamp_session::~wamp_session()
{
  // note: don't log in here, just in case logger has been deleted

  // request IO closure and wait for IO thread to complete its callbacks
  // in this object, before we start deleting members
  close().wait();
}


std::shared_future<void> wamp_session::close()
{
  // ANY thread

  /* Initiate the asynchronous close request. The sequence starts with a call to
   * close the underlying socket object.
   */

  if (m_state == eClosing || m_state == eClosed)
  {
    /* dont need to do anything */
  }
  else
  {
    change_state(eClosing, eClosing);
    try
    {
      m_socket->close();
    }
    catch (...) { /* ignore exceptions due to socket already closed */ }
  }

  return m_shfut_has_closed;
}

/* Called on the IO thread when the underlying tcp_socket object has closed all
 * its socket related resources (eg the tcp socket and timers).  This is the
 * last call that will be received on the IO thread.
 */
void wamp_session::io_on_close()
{
  std::cout << "wamp_session::io_on_close" << std::endl;
  change_state(eClosed,eClosed);

  // push the final EV operation
  std::weak_ptr<wamp_session> wp = m_self_weak;
  auto user_cb = m_notify_state_change_fn;
  m_kernel->get_event_loop()->dispatch(
    [wp, user_cb]()
    {
      /* EV thread */
      // if (auto sp=wp.lock())
      // {
      //   std::cout << std::this_thread::get_id() << " " << "EV calling sp->m_notify_state_change_fn -->" << "\n";
      //   sp->m_notify_state_change_fn(sp, false);
      //   std::cout << std::this_thread::get_id() << " " << "EV calling sp->m_notify_state_change_fn <--" << "\n";
      // }
      user_cb(wp, false);
    } );

  // setting the promise must be very last act in this method, since it likely
  // this object will proceed to be deleted upon this event
  m_has_closed.set_value();
}


void wamp_session::io_on_read(char* src, size_t len)
{
  /* IO thread */

  // std::string temp(src,len);
  // std::cout << "recv: bytes " << len << ": " << temp << "\n";

  try
  {
    m_proto->io_on_read(src,len);
  }
  catch (...)
  {
    handle_exception();
  }
}


void wamp_session::update_state_for_outbound(const jalson::json_array& msg)
{
  int message_type = msg[0].as_uint();

  if (is_passive())
  {
    if (message_type == CHALLENGE)
    {
      change_state(eRecvHello, eSentChallenge);
    }
    else if (message_type == WELCOME)
    {
      change_state(eRecvAuth, eOpen);
    }
    else
    {
      if (m_state != eOpen)
      {
        LOG_ERROR("unexpected message sent while session not open");
        this->close();
      }
    }
  }
  else
  {
    if (message_type == HELLO)
    {
      change_state(eInit, eSentHello);
    }
    else if (message_type == AUTHENTICATE)
    {
      change_state(eRecvChallenge, eSentAuth);
    }
    else
    {
      if (m_state != eOpen)
      {
        LOG_ERROR("unexpected message sent while session not open");
        this->close();
      }
    }
  }

}


const char* wamp_session::state_to_str(wamp_session::SessionState s)
{
  switch (s) {
    case wamp_session::eInit : return "eInit";
    case wamp_session::eRecvHello : return "eRecvHello";
    case wamp_session::eSentChallenge : return "eSentChallenge";
    case wamp_session::eRecvAuth : return "eRecvAuth";
    case wamp_session::eSentHello : return "eSentHello";
    case wamp_session::eRecvChallenge : return "eRecvChallenge";
    case wamp_session::eSentAuth : return "eSentAuth";
    case wamp_session::eOpen : return "eOpen";
    case wamp_session::eClosing : return "eClosing";
    case wamp_session::eClosed : return "eClosed";
    case wamp_session::eStateMax : return "eStateMax";
    default: return "unknown_state";
  };
}


void wamp_session::change_state(SessionState expected, SessionState next)
{
  if (m_state == eClosed) return;

  if (next == eClosed)
  {
    LOG_INFO("session closed #" << m_sid);
    m_state = eClosed;
    return;
  }

  if (next == eClosing)
  {
    m_state = eClosing;
    return;
  }

  if (m_state == expected)
  {
    LOG_INFO("wamp_session state: from " << state_to_str(m_state) << " to " << state_to_str(next));
    m_state = next;

    if (m_state == eOpen)
    {
      // // register for housekeeping
      // std::weak_ptr<wamp_session> wp = handle();
      // hb_func fn = [wp]()
      //   {
      //     if (auto sp = wp.lock())
      //     {
      //       if (sp->is_open())
      //       {
      //         jalson::json_array msg;
      //         msg.push_back(HEARTBEAT);
      //         sp->send_msg(msg);
      //         return true;
      //       }
      //     }
      //     return false; /* remove HB timer */
      //   };
      // m_kernel.get_event_loop()->add_hb_target(std::move(fn));


      if (uses_heartbeats())
      {
        std::weak_ptr<wamp_session> wp = handle();
        m_hb_func = [wp]()
          {
            if (auto sp = wp.lock())
            {
              if (sp->is_open())
              {
                if (sp->duration_since_last() > sp->hb_interval_secs()*MAX_HEARTBEATS_MISSED)
                {
                  sp->drop_connection("wamp.error.session_timeout");
                }
                else
                {
                  jalson::json_array msg;
                  msg.push_back(HEARTBEAT);
                  sp->send_msg(msg);

                  sp->m_kernel->get_event_loop()->dispatch( std::chrono::milliseconds(sp->m_hb_intvl*1000), sp->m_hb_func);
                }
              }
            }
            return 0;
          };
        m_kernel->get_event_loop()->dispatch( std::chrono::milliseconds(m_hb_intvl*1000), m_hb_func);
      }
    }

  }
  else
  {
    LOG_ERROR("wamp_session state failure, cannot move from " << state_to_str(m_state) << " to " << state_to_str(next) );
  }

}


void wamp_session::process_message(unsigned int message_type,
                                   jalson::json_array& ja)
{
  /* EV thread */

  if (m_state == eClosing || m_state == eClosed) return;

  m_time_last_msg_recv = time(NULL);

  try
  {
    /* session state validation */

    if (message_type == ABORT)
    {
      LOG_WARN("received ABORT from peer, closing session");
      close();
      return;
    }

    if (is_passive())
    {
      if (message_type == HELLO)
      {
        change_state(eInit, eRecvHello);
        handle_HELLO(ja);
        return;
      }
      else if (message_type == AUTHENTICATE)
      {
        change_state(eSentChallenge, eRecvAuth);
        handle_AUTHENTICATE(ja);
        return;
      }
      else
      {
        if (m_state != eOpen)
          throw protocol_error("received request before session is open");
      }

      switch (message_type)
      {
        case CALL :
          process_inbound_call(ja);
          return;

        case YIELD :
          process_inbound_yield(ja);
          return;

        case PUBLISH :
          process_inbound_publish(ja);
          return;

        case SUBSCRIBE :
          process_inbound_subscribe(ja);
          return;

        case UNSUBSCRIBE :
          process_inbound_unsubscribe(ja);
          return;

        case REGISTER :
          process_inbound_register(ja);
          return;

        case ERROR :
          process_inbound_error(ja);
          return;

        case HEARTBEAT: return;

        default:
          std::ostringstream os;
          os << "unknown message type " << (int)message_type;
          throw protocol_error(os.str());
      }
    }
    else
    {

      if (message_type == CHALLENGE)
      {
        change_state(eSentHello, eRecvChallenge);
        handle_CHALLENGE(ja);
        return;
      }
      else if (message_type == WELCOME)
      {
        change_state(eSentAuth, eOpen);
        if (m_state == eOpen)
          notify_session_open();
        return;
      }
      else
      {
        if (m_state != eOpen)
          throw protocol_error("received request before session is open");
      }

      switch (message_type)
      {
        case REGISTERED :
          process_inbound_registered(ja);
          return;

        case INVOCATION :
          process_inbound_invocation(ja);
          return;

        case SUBSCRIBED :
          process_inbound_subscribed(ja);
          return;

        case UNSUBSCRIBED :
          // TODO: process_inbound_unsubscribed(ja);
          return;

        case EVENT :
          process_inbound_event(ja);
          return;

        case RESULT :
          process_inbound_result(ja);
          return;

        case ERROR :
          process_inbound_error(ja);
          return;

        case HEARTBEAT: return;

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
    LOG_WARN("handhake error: " << e.what());
    this->close();
  }
  catch ( auth_error& e )
  {
    LOG_WARN("auth error: " << e.what());
    drop_connection(e.error_uri());
  }
  catch ( protocol_error& e )
  {
    LOG_WARN("protocol error: " << e.what());
    drop_connection(WAMP_ERROR_BAD_PROTOCOL);
  }
  catch (wamp_error & e)
  {
    // We don't expect a wamp_error here; they are intended to be caught inside
    // the relevant process method.
    LOG_WARN("unexpected wamp error: " << e.what());
    drop_connection(e.error_uri());
  }
  catch (std::exception & e)
  {
    LOG_WARN("exception: " << e.what());
    drop_connection(WAMP_RUNTIME_ERROR);
  }
  catch (...)
  {
    LOG_WARN("unknown exception");
    drop_connection(WAMP_RUNTIME_ERROR);
  }
}


void wamp_session::send_msg(jalson::json_array& jv, bool)
{
  if (m_state == eClosing || m_state == eClosed) return;

  update_state_for_outbound(jv);

  m_proto->send_msg(jv);
}


void wamp_session::handle_HELLO(jalson::json_array& ja)
{
  /* EV thread */

  std::string realm = ja.at(1).as_string();
  const jalson::json_object & authopts = ja.at(2).as_object();
  std::string authid = jalson::get_copy(authopts, "authid", "").as_string();

  if (realm.empty())
    throw auth_error(WAMP_ERROR_NO_SUCH_REALM, "empty realm not allowed");

  {
    // update the realm & authid, and protect from multiple assignments to the
    // value, so that it cannot be changed once set
    std::unique_lock<std::mutex> guard(m_realm_lock);
    if (m_realm.empty())  m_realm  = realm;
    if (m_authid.empty()) m_authid = authid;
  }

  if (m_auth_proivder.permit_user_realm(authid, realm) == false)
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "auth_provider rejected user/realm");

  /* verify the supported auth methods */

  // look for the "wampcra"
  bool wampcra_found = false;
  jalson::json_array methods = jalson::get_copy(authopts,"authmethods", jalson::json_value::make_array()).as_array();
  for (size_t i = 0; i < methods.size() && !wampcra_found; ++i)
  {
    if ( methods[i].is_string() )
    {
      std::string str = methods[i].as_string();
      if (str == "wampcra") wampcra_found = true;
    }
  }

  if (!wampcra_found)
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "no supported auth method advertised during logon");

  /* Construct the challenge */

  jalson::json_object challenge;
  challenge["nonce"] = random_ascii_string(30);
  challenge["authprovider"] = m_auth_proivder.provider_name(realm);
  challenge["authid"] = authid;
  challenge["timestamp"] = iso8601_utc_timestamp();
  challenge["authrole"] = "user";
  challenge["authmethod"] = "wampcra";
  challenge["session"] = std::to_string( unique_id() );
  std::string challengestr = jalson::encode( challenge );

  {
    std::unique_lock<std::mutex> guard(m_realm_lock);
    if (m_challenge.empty())
      m_challenge = challengestr;
    else
      throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                       "challenge already issued");
  }

  jalson::json_array msg({
    CHALLENGE,
    "wampcra",
    jalson::json_object({{"challenge", std::move(challengestr)}})});
  send_msg( msg );
}


void wamp_session::handle_CHALLENGE(jalson::json_array& ja)
{
  /* EV thread */

  if (ja.size() < 3)
    throw protocol_error("message requires length 3");

  if (!ja[1].is_string())
    throw protocol_error("AuthMethod must be string");

  if (!ja[2].is_object())
    throw protocol_error("Extra must be dict");

  std::string authmethod = ja[1].as_string();
  if (authmethod != "wampcra")
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "unknown AuthMethod (only wampcra supported)");

  const jalson::json_object & extra = ja[2].as_object();
  std::string challmsg = jalson::get_copy(extra, "challenge", "").as_string();
  if (challmsg == "")
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "challenge not found in Extra");

  /* generate the authentication digest */

  std::string key = m_client_secret_fn();

  char digest[256];
  unsigned int digestlen = sizeof(digest)-1;
  memset(digest, 0, sizeof(digest));

  int err = compute_HMACSHA256(key.c_str(), key.size(),
                               challmsg.c_str(), challmsg.size(),
                               digest, &digestlen,
                               HMACSHA256_Mode::BASE64);

  if (err == 0)
  {
    jalson::json_array msg;
    msg.push_back( AUTHENTICATE );
    msg.push_back( digest );
    msg.push_back( jalson::json_object()  );
    send_msg( msg );
  }
  else
  {
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "failed to compute HMAC SHA256 diget");
  }

}


void wamp_session::handle_AUTHENTICATE(jalson::json_array& ja)
{
  /* EV thread */

  std::string orig_challenge;
  {
    std::unique_lock<std::mutex> guard(m_realm_lock);
    orig_challenge = m_challenge;
  }

  std::string key = m_auth_proivder.get_user_secret(m_authid, m_realm);

  char digest[256];
  unsigned int digestlen = sizeof(digest)-1;
  memset(digest, 0, sizeof(digest));

  int r = compute_HMACSHA256(key.c_str(), key.size(),
                             orig_challenge.c_str(), orig_challenge.size(),
                             digest, &digestlen,
                             HMACSHA256_Mode::BASE64);
  for (size_t i = 0; i < key.size(); i++) key[i]='\0';
  if (r == -1)
  {
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "HMAC SHA256 failed");
  }

  // the digest generated by the peer
  const std::string & peer_digest = ja[1].as_string();

  if (digest == peer_digest)
  {
    jalson::json_object details;
    details["roles"] = jalson::json_object( {
        {"broker", jalson::json_value::make_object()},
        {"dealer", jalson::json_value::make_object()}} );

    jalson::json_array msg {
      WELCOME,
        m_sid,
        std::move( details )
        };

    send_msg( msg );

    if (m_state == eOpen)
      notify_session_open();
  }
  else
  {
    throw auth_error(WAMP_ERROR_AUTHORIZATION_FAILED,
                     "client failed challenge-response-authentication");
  }
}


/* Notify any callback of state change to open. This is deliberately performed
 * on the event thread, to prevent IO thread going into user code.
 */
void wamp_session::notify_session_open()
{
  /* EV thread */

  if (m_notify_state_change_fn)
    m_notify_state_change_fn(shared_from_this(), true /* session is open */);

  m_promise_on_open.set_value();
}


bool wamp_session::is_open() const
{
  return m_state == eOpen;
}


bool wamp_session::is_pending_open() const
{
  return (m_state != eOpen && m_state != eClosed && m_state != eClosing);
}


std::future<void> wamp_session::initiate_hello(client_credentials cc)
{
  /* USER thread */

  if (!cc.secret_fn)
    throw std::runtime_error("user-secret function cannot be undefined");

  {
    std::unique_lock<std::mutex> guard(m_realm_lock);

    if (cc.realm.empty())
      throw std::runtime_error("realm cannot be empty");

    if (!m_realm.empty())
      throw std::runtime_error("initiate_hello cannot be called more than once");

    if (m_realm.empty()) m_realm = cc.realm;
  }

  m_client_secret_fn = std::move( cc.secret_fn );

  auto initiate_cb = [this, cc]()
    {
      jalson::json_object roles ({
          {"publisher",  jalson::json_object()},
          {"subscriber", jalson::json_object()},
          {"caller",     jalson::json_object()},
          {"callee",     jalson::json_object()}
        });

      jalson::json_array msg { jalson::json_value(HELLO), jalson::json_value(cc.realm) };
      jalson::json_object& opt = jalson::append_object( msg );

      opt[ "roles" ] = std::move( roles );
      opt[ "agent" ] = "XXX-1.0"; // TODO: update with project name
      opt[ "authid"] = std::move(cc.authid);

      jalson::json_array& ja = jalson::insert_array(opt, "authmethods");
      for (auto item : cc.authmethods)
        ja.push_back( std::move(item) );

      send_msg( msg );
    };

  m_proto->initiate(std::move(initiate_cb));

  return m_promise_on_open.get_future();
}


int wamp_session::duration_since_last() const
{
  return (time(NULL) - m_time_last_msg_recv);
}


int wamp_session::duration_since_creation() const
{
  return (time(NULL) - m_time_create);
}


const std::string& wamp_session::realm() const
{
  // need this lock, because realm might be updated from IO thread during logon
  std::unique_lock<std::mutex> guard(m_realm_lock);
  return m_realm;
}


t_request_id wamp_session::provide(std::string uri,
                                   const jalson::json_object& options,
                                   rpc_cb cb,
                                   void * data)
{
  jalson::json_array msg;
  msg.push_back( REGISTER );
  msg.push_back( 0 );
  msg.push_back( options );
  msg.push_back( uri );


  procedure p;
  p.uri = uri;
  p.user_cb = cb;
  p.user_data = data;

  t_request_id request_id;
  {
    std::unique_lock<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::unique_lock<std::mutex> guard(m_pending_lock);
      m_pending_register[request_id] = p;
    }

    send_msg( msg );
  }

  LOG_INFO("Sending REGISTER request for proc '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_registered(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id  = extract_request_id(msg, 1);

  if (!msg[2].is_uint())
    throw protocol_error("registration ID must be unsigned int");
  uint64_t registration_id = msg[2].as_uint();

  std::unique_lock<std::mutex> guard(m_pending_lock);
  auto iter = m_pending_register.find( request_id );

  if (iter != m_pending_register.end())
  {
    m_procedures[registration_id] = iter->second;
    m_pending_register.erase(iter);

    LOG_INFO("procedure '"<< m_procedures[registration_id].uri <<"' registered"
           << " with registration_id " << registration_id);
  }

}


void wamp_session::process_inbound_invocation(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_uint())
    throw protocol_error("registration ID must be unsigned int");
  uint64_t registration_id = msg[2].as_uint();

  // find the procedure
  try
  {
    auto iter = m_procedures.find(registration_id);

    if (iter == m_procedures.end())
      throw wamp_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION);

    std::string uri = iter->second.uri;

    XXX:: wamp_invocation invoke;
    invoke.user = iter->second.user_data;

    if ( msg.size() > 4 ) invoke.arg_list = std::move(msg[4].as_array());
    if ( msg.size() > 5 ) invoke.arg_dict = std::move(msg[4].as_object());

    session_handle wp = this->handle();
    invoke.yield = [wp,request_id](jalson::json_array arg_list, jalson::json_object arg_dict)
      {
        wamp_args args { arg_list, arg_dict };
        if (auto sp = wp.lock())
          sp->invocation_yield(request_id, std::move(args));
      };

    invoke.error = [wp,request_id](std::string error_uri,jalson::json_array arg_list, jalson::json_object arg_dict)
      {
        wamp_args args { arg_list, arg_dict };
        if (auto sp = wp.lock())
          sp->reply_with_error(INVOCATION, request_id, std::move(args), std::move(error_uri));
      };

    {
      if (user_cb_allowed()) iter->second.user_cb(invoke);
    }

  }
  catch (XXX::wamp_error& ex)
  {
    reply_with_error(INVOCATION, request_id, ex.args(), ex.error_uri());
  }
}


t_request_id wamp_session::subscribe(const std::string& uri,
                                const jalson::json_object& options,
                                subscription_cb cb,
                                void * user)
{
  jalson::json_array msg;
  msg.push_back( SUBSCRIBE );
  msg.push_back( 0 );
  msg.push_back( options );
  msg.push_back( uri );

  subscription sub;
  sub.uri = uri;
  sub.user_cb = cb;
  sub.user_data = user;

  t_request_id request_id;
  {
    std::unique_lock<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::unique_lock<std::mutex> guard(m_pending_lock);
      m_pending_subscribe[request_id] = std::move(sub);
    }
    send_msg( msg );
  }

  LOG_INFO("Sending SUBSCRIBE request for topic '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_subscribed(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id  = extract_request_id(msg, 1);

  if (!msg[2].is_uint())
      throw protocol_error("subscription ID must be unsigned int");
  t_subscription_id subscription_id = msg[2].as_uint();

  subscription temp;
  bool found = false;
  {
    std::unique_lock<std::mutex> guard(m_pending_lock);
    auto iter = m_pending_subscribe.find( request_id );

    if (iter != m_pending_subscribe.end())
    {
      found = true;
      temp = iter->second;

      m_subscriptions[subscription_id] = std::move(iter->second);
      m_pending_subscribe.erase(iter);
    }
  }


  if (found)
  {
    LOG_INFO("Subscribed to topic '"<< temp.uri <<"'"
           << " with  subscription_id " << subscription_id);

    // user callback
    if (temp.user_cb)
      try
      {
        if (user_cb_allowed())
        {
          wamp_subscription_event ev;
          ev.type = wamp_subscription_event::started;
          ev.uri = temp.uri;
          temp.user_cb( ev );
        }

      } catch(...){ log_exception(__logger, "inbound subscribed user callback"); }
  }
}


void wamp_session::process_inbound_event(jalson::json_array & msg)
{
  /* EV thread */

  t_subscription_id subscription_id = msg[1].as_uint();
  jalson::json_object details = std::move(msg.at(3).as_object());
  jalson::json_value * ptr_args_list = jalson::get_ptr(msg, 4); // optional
  jalson::json_value * ptr_args_dict = jalson::get_ptr(msg, 5); // optional

  const jalson::json_array  & args_list = ptr_args_list? ptr_args_list->as_array()  : jalson::json_array();
  const jalson::json_object & args_dict = ptr_args_dict? ptr_args_dict->as_object() : jalson::json_object();

  auto iter = m_subscriptions.find(subscription_id);
  if (iter !=m_subscriptions.end())
  {
    try {
      if (user_cb_allowed())
      {
        wamp_subscription_event ev;
        ev.type = wamp_subscription_event::update;
        ev.uri  = iter->second.uri;
        ev.details = std::move( details );
        ev.args.args_list = args_list;
        ev.args.args_dict = args_dict;
        ev.user = iter->second.user_data;
        iter->second.user_cb( ev );
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
                                const jalson::json_object& options,
                                wamp_args args,
                                wamp_call_result_cb user_cb,
                                void* user_data)
{
  /* USER thread */

  jalson::json_array msg;
  msg.push_back( CALL );
  msg.push_back( 0 );
  msg.push_back( options );
  msg.push_back( uri );
  msg.push_back( args.args_list );
  msg.push_back( args.args_dict );

  wamp_call mycall;
  mycall.user_cb = user_cb;
  mycall.user_data = user_data;
  mycall.rpc= uri;

  t_request_id request_id;
  {
    std::unique_lock<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::unique_lock<std::mutex> guard(m_pending_lock);
      m_pending_call[request_id] = std::move(mycall);
    }

    send_msg( msg );
  }

  LOG_INFO("Sending CALL request for  '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_result(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id  = extract_request_id(msg, 1);

  if (!msg[2].is_object())
      throw protocol_error("details must be json object");
  jalson::json_object & options = msg[2].as_object();

  wamp_call orig_call;

  {
    std::unique_lock<std::mutex> guard(m_pending_lock);
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
    wamp_call_result r;
    r.was_error = false;
    r.procedure = orig_call.rpc;
    r.user = orig_call.user_data;
    if (msg.size()>3) r.args.args_list = std::move(msg[3].as_array());
    if (msg.size()>4) r.args.args_dict = std::move(msg[4].as_object());
    r.details = options;

    try {
      if (user_cb_allowed()) orig_call.user_cb(std::move(r));
    }
    catch(...) {
      log_exception(__logger, "inbound result user callback");
    }
  }

}


/* Handles errors for both active & passive sessions */
void wamp_session::process_inbound_error(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 5);

  int orig_request_type = msg[1].as_int();
  t_request_id request_id = extract_request_id(msg, 2);
  jalson::json_object & details = msg[3].as_object();
  std::string& error_uri = msg[4].as_string();

  if (is_passive())
  {
    switch (orig_request_type)
    {
      case INVOCATION:
      {
        wamp_invocation orig_request;

        {
          std::unique_lock<std::mutex> guard(m_pending_lock);
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
          orig_request.reply_fn(args, std::move(error_ptr));
        } catch (...) {
          log_exception(__logger, "inbound invocation error user callback");
        }

        break;
      }
      default:
        LOG_WARN("wamp error response has unexpected request type " << orig_request_type);
        break;
    }
  }
  else
  {
    switch (orig_request_type)
    {
      case CALL :
      {
        wamp_call orig_call;
        bool found = false;

        {
          std::unique_lock<std::mutex> guard(m_pending_lock);
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
            wamp_call_result r;
            r.was_error = true;
            r.error_uri = error_uri;
            r.procedure = orig_call.rpc;
            r.user = orig_call.user_data;
            if ( msg.size() > 5 ) r.args.args_list = msg[5].as_array();
            if ( msg.size() > 6 ) r.args.args_dict = msg[6].as_object();
            r.details = details;

            try {
              if (user_cb_allowed()) orig_call.user_cb(std::move(r));
            }
            catch(...){ log_exception(__logger, "inbound call error user callback");}
          }
        }
        else
        {
          LOG_WARN("no pending call associated with call error response, for request_id "
                   << request_id);
        }
        break;
      }
      default:
        LOG_WARN("wamp error response has unexpected request type " << orig_request_type);
        break;
    }
  }
}


t_request_id wamp_session::publish(std::string uri,
                                   const jalson::json_object& options,
                                   wamp_args args)
{
  /* USER thread */

  jalson::json_array msg;
  msg.push_back( PUBLISH );
  msg.push_back( 0 );
  msg.push_back( options );
  msg.push_back( uri );
  if (!args.args_list.empty())
  {
    msg.push_back( args.args_list );
    if (!args.args_dict.empty()) msg.push_back( args.args_dict );
  }

  t_request_id request_id;

  {
    std::unique_lock<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    send_msg( msg );
  }

  return request_id;
}


void wamp_session::process_inbound_call(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[3].is_string()) throw protocol_error("procedure uri must be string");
  std::string procedure_uri = std::move(msg[3].as_string());

  wamp_args my_wamp_args;
  if ( msg.size() > 4 ) my_wamp_args.args_list = msg[4].as_array();
  if ( msg.size() > 5 ) my_wamp_args.args_dict = msg[5].as_object();


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
          jalson::json_array msg;
          msg.push_back(RESULT);
          msg.push_back(request_id);
          msg.push_back(jalson::json_object());
          if (!args.args_list.empty())
          {
            msg.push_back( args.args_list );
            if (!args.args_dict.empty()) msg.push_back( args.args_dict );
          }
          sp->send_msg( msg );
        }
        else
        {
          jalson::json_array msg;
          msg.push_back(ERROR);
          msg.push_back(CALL);
          msg.push_back(request_id);
          msg.push_back(jalson::json_object());
          msg.push_back(*error_uri);
          if (!args.args_list.empty())
          {
            msg.push_back( args.args_list );
            if (!args.args_dict.empty()) msg.push_back( args.args_dict );
          }
          sp->send_msg( msg );
        }
      }
    };

  m_server_handler.inbound_call(this, procedure_uri, std::move(my_wamp_args), std::move(reply_fn));
}


/* perform outbound invocation request */
t_request_id wamp_session::invocation(uint64_t registration_id,
                                      const jalson::json_object& options,
                                      wamp_args args,
                                      wamp_invocation_reply_fn fn)
{
  /* EV & USER thread */

  jalson::json_array msg;
  msg.push_back( INVOCATION );
  msg.push_back( 0 );
  msg.push_back( registration_id );
  msg.push_back( options );

  if (!args.args_list.empty())
  {
    msg.push_back( args.args_list );
    if (!args.args_dict.empty()) msg.push_back( args.args_dict );
  }

  t_request_id request_id;
  wamp_invocation my_invocation;
  my_invocation.reply_fn = fn;

  {
    std::unique_lock<std::mutex> guard(m_request_lock);

    request_id = m_next_request_id++;
    msg[1] = request_id;

    {
      std::unique_lock<std::mutex> guard(m_pending_lock);
      m_pending_invocation[request_id] = std::move(my_invocation);
    }

    send_msg( msg );
  }

  return  request_id;
}


void wamp_session::process_inbound_yield(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  wamp_args args;
  if ( msg.size() > 3 ) args.args_list = msg[3].as_array();
  if ( msg.size() > 4 ) args.args_dict = msg[4].as_object();

  auto iter = m_pending_invocation.find(request_id);
  if (iter != m_pending_invocation.end())
  {
    if (iter->second.reply_fn)
    {
      try {
        iter->second.reply_fn(args, nullptr);
      } catch (...){}
    }
    m_pending_invocation.erase(iter);
  }

}


void wamp_session::process_inbound_publish(jalson::json_array & msg)
{
  /* EV thread */

  if (m_server_handler.handle_inbound_publish)
  {
    check_size_at_least(msg.size(), 4);

    if (!msg[2].is_object())
      throw protocol_error("options must be json object");

    if (!msg[3].is_string()) throw protocol_error("topic uri must be string");

    wamp_args args;
    if ( msg.size() > 4 ) args.args_list = std::move(msg[4].as_array());
    if ( msg.size() > 5 ) args.args_dict = std::move(msg[5].as_object());

    m_server_handler.handle_inbound_publish(this, std::move(msg[3].as_string()), std::move(msg[2].as_object()), args);
  }
}


void wamp_session::process_inbound_subscribe(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_object()) throw protocol_error("options must be json object");
  if (!msg[3].is_string()) throw protocol_error("topic uri must be string");

  std::string topic_uri = std::move(msg[3].as_string());

  try
  {
    m_server_handler.inbound_subscribe(this, request_id, topic_uri, msg[2].as_object());
  }
  catch(wamp_error& ex)
  {
    reply_with_error(SUBSCRIBE, request_id, ex.args(), ex.error_uri());
  }
}



void wamp_session::process_inbound_unsubscribe(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 3);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[2].is_uint()) throw protocol_error("subscription id must be uint");
  t_subscription_id sub_id = msg[2].as_uint();

  try
  {
    m_server_handler.inbound_unsubscribe(this, request_id, sub_id);
  }
  catch(wamp_error& ex)
  {
    reply_with_error(UNSUBSCRIBE, request_id, ex.args(), ex.error_uri());
  }
}



void wamp_session::process_inbound_register(jalson::json_array & msg)
{
  /* EV thread */

  check_size_at_least(msg.size(), 4);

  t_request_id request_id = extract_request_id(msg, 1);

  if (!msg[3].is_string())
    throw protocol_error("procedure uri must be string");
  std::string uri = std::move(msg[3].as_string());

  try
  {
    uint64_t registration_id = m_server_handler.inbound_register(handle(),
                                                                 realm(),
                                                                 std::move(uri));

    jalson::json_array resp;
    resp.push_back(REGISTERED);
    resp.push_back(request_id);
    resp.push_back(registration_id);
    send_msg(resp);
  }
  catch(wamp_error& ex)
  {
    reply_with_error(REGISTER, request_id, ex.args(), ex.error_uri());
  }
}



/* reply to an invocation with a yield message */
void wamp_session::invocation_yield(int request_id,
                                    wamp_args args)
{
  jalson::json_array msg;

  msg.push_back(YIELD);
  msg.push_back(request_id);
  msg.push_back(jalson::json_object());

  if (!args.args_list.empty())
  {
    msg.push_back(args.args_list);
    if (!args.args_dict.empty()) msg.push_back(args.args_dict);
  }

  send_msg(msg);
}


void wamp_session::reply_with_error(
  int request_type,
  int request_id,
  wamp_args args,
  std::string error_uri)
{
  jalson::json_array msg;

  msg.push_back(ERROR);
  msg.push_back(request_type);
  msg.push_back(request_id);
  msg.push_back(jalson::json_object());
  msg.push_back(error_uri);

  if (!args.args_list.empty())
  {
    msg.push_back(args.args_list);
    if (!args.args_dict.empty()) msg.push_back(args.args_dict);
  }

  send_msg(msg);
}


bool wamp_session::uses_heartbeats() const
{
  return m_hb_intvl > 0;
}


void wamp_session::drop_connection(std::string errmsg)
{
  LOG_WARN("closing session #" << unique_id() << ", err: " << errmsg);

  jalson::json_array msg;
  if (is_open())
    msg.push_back( GOODBYE );
  else
    msg.push_back( ABORT );
  msg.push_back( jalson::json_object() );
  msg.push_back( std::move(errmsg) );
  try
  {
    send_msg( msg, true );
  }
  catch (...) { /* ignore, we are closing anyway */ }

  std::weak_ptr<wamp_session> wp = handle();
  m_kernel->get_event_loop()->dispatch(
    std::chrono::milliseconds(250),
    [wp]()
    {
      if (auto sp = wp.lock()) sp->close();
      return 0;
    });
}

bool wamp_session::is_passive() const
{
  return m_proto->mode() == protocol::connection_mode::ePassive;
}


} // namespace XXX
