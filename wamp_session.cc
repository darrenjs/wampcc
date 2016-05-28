#include "wamp_session.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "WampTypes.h"
#include "event_loop.h"
#include "Logger.h"
#include "utils.h"
#include "kernel.h"

#include <jalson/jalson.h>

#include <memory>
#include <iomanip>
#include <iostream>

#include <string.h>
#include <unistd.h>


#define HEADERLEN 4 /* size of uint32 */
#define INBOUND_BUFFER_SIZE 2000 // TODO: increase




namespace XXX {

/* exception that represents a protocol level error, and will result in
 * termination of the connection */
class session_error : public std::runtime_error
{
public:
  enum error_code
  {
    no_error = 0,
    msgbuf_full,
    bad_protocol,
    unknown,
    bad_json,
  };

  std::string uri;
  error_code err;

  session_error(const std::string& __uri,
                error_code __e,
                const std::string& __text="")
  : std::runtime_error( __text ),
    uri( __uri ),
    err( __e )
  {
  }
};



static std::atomic<uint64_t> m_next_id(1); // start at 1, so that 0 implies invalid ID
static uint64_t generate_unique_session_id()
{
  return m_next_id++;
}


/* Constructor */
  wamp_session::wamp_session(kernel& __kernel,
                             IOHandle* h,
                             bool is_passive,
                             std::string __realm,
                             session_state_fn state_cb,
                             std::shared_ptr<wamp_session>& outref,
                             server_msg_handler handler)
  : m_state( eInit ),
    __logptr(__kernel.get_logger()),
    m_kernel(__kernel),
    m_sid( generate_unique_session_id() ),
    m_handle( h ),
    m_hb_intvl(2),  // TODO HB's are not being sent at this rate
    m_time_create(time(NULL)),
    m_time_last_msg_recv(time(NULL)),
    m_next_request_id(1),
    m_buf( new char[ INBOUND_BUFFER_SIZE ] ),
    m_bytes_avail(0),
    m_is_passive(is_passive),
    m_realm(__realm),
    m_notify_state_change_fn(state_cb),
    m_server_handler(handler),
    m_user_cb_allowed(true)
{
  // need to create a sp<> before can use shared_from_this()
  outref = std::shared_ptr<wamp_session>(this);
  m_handle->set_listener( shared_from_this() );
}


std::shared_ptr<wamp_session> wamp_session::create(kernel& k,
                                                   IOHandle * ioh,
                                                   bool is_passive,
                                                   std::string realm,
                                                   session_state_fn state_cb,
                                                   server_msg_handler handler)
{
  std::shared_ptr<wamp_session> sp;
  new wamp_session(k, ioh, is_passive, realm, state_cb, sp, handler);
  return sp;
}


/* Destructor */
wamp_session::~wamp_session()
{
  // note: dont log in here, just in case logger has been deleted
  std::cout << "wamp_session::~wamp_session\n";
  delete [] m_buf;
}

uint64_t wamp_session::unique_id()
{
  return m_sid;
}

//----------------------------------------------------------------------

void wamp_session::close()
{
  // ANY thread
  change_state(eClosing, eClosing);
  std::lock_guard<std::mutex> guard(m_handle_lock);
  if (m_handle) m_handle->request_close();
}

//----------------------------------------------------------------------

void wamp_session::io_on_close()
{
  /* IO thread */

  _DEBUG_("wamp_session::io_on_close");

  // following the call of this callback, we must not call the IO handle again
  {
    std::lock_guard<std::mutex> guard(m_handle_lock);
    m_handle = nullptr;
  }

  // perform all other notification on the event thread
  std::weak_ptr<wamp_session> wp = handle();
  m_kernel.get_event_loop()->dispatch( [wp]() {
      if (auto sp = wp.lock())
        sp->change_state(eClosed,eClosed);
    } );
}

//----------------------------------------------------------------------
void wamp_session::io_on_read(char* src, size_t len)
{
  /* IO thread */

  std::string temp(src,len);
  std::cout << "recv: bytes " << len << ": " << temp << "\n";


  session_error::error_code err_code = session_error::no_error;
  std::string err_uri;
  std::string err_text;

  try
  {
    io_on_read_impl(src, len);
  }
  catch ( session_error& e )
  {
    err_code = e.err;
    err_uri  = std::move(e.uri);
    err_text = e.what();
  }
  catch ( std::exception& e )
  {
    err_code = session_error::unknown;
    err_uri = WAMP_RUNTIME_ERROR;
    err_text = e.what();
  }
  catch (...)
  {
    err_code = session_error::unknown;
    err_uri = WAMP_RUNTIME_ERROR;
  }

  if (err_code != session_error::no_error)
  {
    _ERROR_("session_error: err_code " << err_code
            << ", uri=" << err_uri
            << ", text=" << err_text);
    try
    {
      // TODO: this does not seem to get sent.  Probably the socket is getting
      // closed before the message is written.
      jalson::json_array msg;
      jalson::json_object error_dict;
      msg.push_back( GOODBYE );
      msg.push_back( jalson::json_object() );
      msg.push_back( err_uri );
      this->send_msg( msg );
    } catch (...){ log_exception(__logptr, "send_msg for outbound goodbye"); }

    this->close();
  }

}


void wamp_session::io_on_read_impl(char* src, size_t len)
{
  /* IO thread */

  while (len > 0)
  {
    size_t buf_space_avail = INBOUND_BUFFER_SIZE - m_bytes_avail;
    if (buf_space_avail)
    {
      size_t bytes_to_consume = std::min(buf_space_avail, len);
      memcpy(m_buf + m_bytes_avail, src, bytes_to_consume);
      src += bytes_to_consume;
      len -= bytes_to_consume;
      m_bytes_avail += bytes_to_consume;


      /* TODO: a problem that might occur here is that a bad message will be
       * recieved, like 'XXXX' for the length, and we will need to then wait until
       * we get that many bytes until we can move onto processing the message and
       * discovering it is a bad protocol. So need to beable to switch on some kind
       * of logging here. */


      /* process the data in the working buffer */

      char* ptr = m_buf;
      while (m_bytes_avail)
      {
        if (m_bytes_avail < HEADERLEN) break; // header incomplete

        // quick protocol check
        if (m_bytes_avail > HEADERLEN)
        {
          char firstchar = *(ptr + HEADERLEN);
          if (firstchar != '[')
            throw session_error(WAMP_RUNTIME_ERROR, session_error::bad_protocol, "bad json message");
        }

        uint32_t msglen =  ntohl( *((uint32_t*) ptr) );
        if (m_bytes_avail < (HEADERLEN+msglen)) break; // body incomplete

        // we have enough bytes to decode
        this->decode_and_process(ptr+HEADERLEN, msglen);

        // skip to start of next message
        ptr           += (HEADERLEN+msglen);
        m_bytes_avail -= (HEADERLEN+msglen);
      }

      /* move any left over bytes to the head of the buffer */
      if (m_bytes_avail && (m_buf != ptr)) memmove(m_buf, ptr, m_bytes_avail);
    }
    else
    {
      throw session_error(WAMP_RUNTIME_ERROR, session_error::msgbuf_full, "msg buffer full");
    }
  }
}
//----------------------------------------------------------------------

void wamp_session::decode_and_process(char* ptr, size_t msglen)
{
  /* IO thread */

  try
  {
    jalson::json_value jv;
    jalson::decode(jv, ptr, msglen);

    /* sanity check message */
    jalson::json_array& msg = jv.as_array();

    if (msg.size() == 0)
      throw session_error(WAMP_RUNTIME_ERROR, session_error::bad_protocol, "json array empty");

    if (!msg[0].is_uint())
      throw session_error(WAMP_RUNTIME_ERROR, session_error::bad_protocol, "message type must be uint");
    unsigned int messasge_type = msg[0].as_uint();

    /* process on the EV thread */
    std::weak_ptr<wamp_session> wp = handle();
    std::function<void()> fn = [wp,msg,messasge_type]() mutable
      {
        if (auto sp = wp.lock())
          sp->process_message(messasge_type, msg);
      };
    m_kernel.get_event_loop()->dispatch(std::move(fn));

  }
  catch( const jalson::json_error& e)
  {
    throw session_error(WAMP_RUNTIME_ERROR, session_error::bad_json, e.what());
  }
}

//----------------------------------------------------------------------

void wamp_session::update_state_for_outbound(const jalson::json_array& msg)
{
  int message_type = msg[0].as_uint();

  if (message_type == ABORT)
  {
    change_state( eClosed, eClosed );
    return;
  }

  if (m_is_passive)
  {

    // TODO: in both this function, and its outbound equivalent, need to have
    // support for CLOSE and ABORT messages.

    if (message_type == CHALLENGE)
    {
      change_state(eRecvHello, eSentChallenge);

      // capture the outbound challenge
      m_challenge= msg;
    }
    else if (message_type == WELCOME)
    {
      change_state(eRecvAuth, eOpen);
    }
    else
    {
      if (m_state != eOpen) this->close(); // TODO: these need to log errors, just like on the inbound
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
      if (m_state != eOpen) this->close();// TODO: these need to log errors, just like on the inbound
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
    _INFO_("session closed #" << m_sid);
    m_state = eClosed;
    notify_session_state_change( false );
    return;
  }

  if (next == eClosing)
  {
    m_state = eClosing;
    return;
  }

  if (m_state == expected)
  {
    _INFO_("wamp_session state: from " << state_to_str(m_state) << " to " << state_to_str(next));
    m_state = next;

    if (m_state == eOpen)
    {
      // register for housekeeping
      std::weak_ptr<wamp_session> wp = handle();
      hb_func fn = [wp]()
        {
          if (auto sp = wp.lock())
          {
            if (sp->is_open())
            {
              jalson::json_array msg;
              msg.push_back(HEARTBEAT);
              sp->send_msg(msg);
              return true;
            }
          }
          return false; /* remove HB timer */
        };
      m_kernel.get_event_loop()->add_hb_target(std::move(fn));
    }

  }
  else
  {
    _ERROR_("wamp_session state failure, cannot move from " << state_to_str(m_state) << " to " << state_to_str(next) );
  }

}

//----------------------------------------------------------------------

void wamp_session::process_message(unsigned int message_type,
                                   jalson::json_array& ja)
{
  // IO thread

//  _DEBUG_( "recv msg: " <<  jv  << ", is_passive: " << m_is_passive);

  if (m_state == eClosing || m_state == eClosed) return;

  m_time_last_msg_recv = time(NULL);

  try
  {
    /* session state validation */

    if (m_is_passive)
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
      else if (message_type == ABORT)
      {
        change_state(eClosed, eClosed);
        handle_ABORT(ja);
        return;
      }
      else
      {
        if (m_state != eOpen) throw session_error(WAMP_RUNTIME_ERROR,
                                                  session_error::bad_protocol,
                                                  "received request but handshake incomplete");
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

        case REGISTER :
          process_inbound_register(ja);
          return;

        case ERROR :
          process_inbound_error(ja); // TODO: have an error handling specific to the kind of session (active/passive)
          return;

        case HEARTBEAT: return;

        default:
          std::ostringstream os;
          os << "unknown message type " << (int)message_type;
          throw session_error(WAMP_RUNTIME_ERROR,
                              session_error::bad_protocol,
                              os.str());
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
        handle_WELCOME(ja);
        if (m_state == eOpen) notify_session_state_change(true);
        return;
      }
      else if (message_type == ABORT)
      {
        _INFO_("recv ABORT from peer");
        change_state(eClosed, eClosed);
        handle_ABORT(ja);
        return;
      }
      else
      {
        if (m_state != eOpen) throw session_error(WAMP_RUNTIME_ERROR,
                                                  session_error::bad_protocol,
                                                  "received request but handshake incomplete");
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

        case EVENT :
          process_inbound_event(ja);
          return;

        case RESULT :
          process_inbound_result(ja);
          return;

        case ERROR :
          process_inbound_error(ja);  // TODO: have an error handling specific to the kind of session (active/passive)
          return;

        case HEARTBEAT: return;

        default:
          std::ostringstream os;
          os << "unknown message type " << (int)message_type;
          throw session_error(WAMP_RUNTIME_ERROR,
                              session_error::bad_protocol,
                              os.str());
      }
    }
    return; // message handled okay
  }
  catch (session_error & e)
  {
    _WARN_("aborting session due to error, uri: " << e.uri << ", what: " << e.what());
  }
  catch (std::exception & e)
  {
    _WARN_("closing session due to exception, what: " << e.what());
  }
  catch (...)
  {
    _WARN_("closing session due to unknown exception");
  }
  this->close();
}


//----------------------------------------------------------------------


void wamp_session::send_msg(jalson::json_array& jv, bool final)
{
  if (m_state != eClosed && m_state != eClosing)
  {
    std::pair<const char*, size_t> bufs[2];

    std::string msg ( jalson::encode( jv ) );

    // write message length prefix
    uint32_t msglen = htonl(  msg.size() );
    bufs[0].first  = (char*)&msglen;
    bufs[0].second = sizeof(msglen);

    // write message
    update_state_for_outbound(jv);
    if (final)
    {
      // TODO: think about how to manage session shutdown
      // m_is_closing = true;
    }
    else
    {
      // write message
      bufs[1].first  = (const char*)msg.c_str();
      bufs[1].second = msg.size();
      this->send_bytes( &bufs[0], 2, final );
    }
  }
}


//----------------------------------------------------------------------

bool wamp_session::send_bytes(std::pair<const char*, size_t>* bufs, size_t count, bool final)
{
  /* EV thread */

  if (m_state != eClosed && m_state != eClosing)
  {
    std::lock_guard<std::mutex> guard(m_handle_lock);
    if (m_handle) m_handle->write_bufs(bufs, count, final);
  }
  return true;
}

//----------------------------------------------------------------------

// TODO: what happens if we throw in here, ie, we are on the Socket IO thread!!!!
void wamp_session::handle_HELLO(jalson::json_array& ja)
{

  /* WAMP:

     [ (0) "HELLO",
       (1) "realm1",
       (2) {
            "roles": {},
            "authid": "peter",
            "authmethods": ["wampcra"]
           }
     ]
  */

//  m_auth.recvHello = true;
//  m_auth.hello_realm = msum.msg->at(1).as_string();
//  m_auth.hello_opts  = msum.msg->at(2).as_object();

  // m_sid = m_auth.hello_opts["authid"].as_string().value();
  // m_sid = m_auth.hello_opts["agentid"].as_string().value();

  std::string realm = ja.at(1).as_string();

  if (realm=="" || realm.empty())
    throw event_error(WAMP_ERROR_NO_SUCH_REALM, "empty realm not allowed", true);

  {
    // update the realm, and protect from multiple assignments to the value, so
    // that it cannot be changed once set
    std::unique_lock<std::mutex> guard(m_realm_lock);
    if (m_realm.empty() && !realm.empty())
      m_realm = realm;
  }

  const jalson::json_object & authopts = ja.at(2).as_object();

  /* TODO: verify the realm */

  // Realm* realm = m_sessman->getRealm(m_auth.hello_realm);
  // if ( realm == NULL)
  // {
  //   _ERROR_("Rejecting HELLO for unknown realm [" << m_auth.hello_realm << "]");
  //   // TODO: abort
  //   abort_authentication("authentication failed",
  //                        "wamp.error.no_such_realm");
  //   return;
  // }

  /* verify the user */

  // get the user id
  std::string authid = jalson::get_copy(authopts, "authid", "").as_string();

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

  if (wampcra_found)
  {
    // TODO: authentication?
  }
  else
  {
    // TODO: need to abort the session
  }


  /* Construct the challenge */

  // TODO: next, we need issue a challenge to the peer

  // TODO: need to serialise this object.  This is mandated by the WAMP spec.
  jalson::json_object challenge;
  challenge["nonce"] = "LHRTC9zeOIrt_9U3";
  challenge["authprovider"] = "userdb";
  challenge["authid"] = "peter";
  challenge["timestamp"] = "2014-06-22T16:36:25.448Z";
  challenge["authrole"] = "user";
  challenge["authmethod"] = "wampcra";
  challenge["session"] = "3251278072152162";
  std::string challengestr = jalson::encode( challenge );   // memleak?

  /*
      [  CHALLENGE,
         AuthMethod|string,
         Extra|dict]
  */
  jalson::json_array msg;
  msg.push_back( CHALLENGE );
  msg.push_back( "wampcra" );
  jalson::append_object(msg)["challenge"] = challengestr;

  send_msg( msg );
}

//----------------------------------------------------------------------

// TODO: what happens if we throw in here, ie, we are on the Socket IO thread!!!!
void wamp_session::handle_CHALLENGE(jalson::json_array& ja)
{
  /* called on IO thread */

  // TODO: parsing code be better. Especially the extraction of 'challenge',
  // this is an example where I want the API to be more expressive.

  // TODO: check authmethod is "wampcra"
  //const std::string & authmethod    = ev->ja[1].as_string();



  const jalson::json_object & extra = ja[2].as_object();
  std::string challmsg = jalson::get_copy(extra, "challenge", "").as_string();

  /* generate the authentication digest */

  // TODO: the secret needs to come from somewhere, and, will probably be salted.
  std::string key ="secret2";

  char digest[256];
  unsigned int digestlen = sizeof(digest)-1;
  memset(digest, 0, sizeof(digest));

  // TODO: check return value
  compute_HMACSHA256(key.c_str(), key.size(),
                     challmsg.c_str(), challmsg.size(),
                     digest, &digestlen,
                     HMACSHA256_BASE64);

  /* build the reply */

  jalson::json_array msg;
  msg.push_back( AUTHENTICATE );
  msg.push_back( digest );
  msg.push_back( jalson::json_object()  );

  send_msg( msg );
}

//----------------------------------------------------------------------


void wamp_session::handle_ABORT(jalson::json_array& /*ja*/)
{
  // TODO: prob need to escalate?
}

/*  Called on the IO thread when we have received a WELCOME message. This will
 *  indicate the the session is now open. Here we will be a client that is
 *  trying to logon to a remote service.
 */
void wamp_session::handle_WELCOME(jalson::json_array& /*ja*/)
{

  /* */
  // TODO: prob need to escalate?
}

//----------------------------------------------------------------------

// TODO: what happens if we throw in here, ie, we are on the Socket IO thread!!!!
void wamp_session::handle_AUTHENTICATE(jalson::json_array& ja)
{
  // TODO: could just store it in the wamp_session ?

  const std::string & orig_challenge = m_challenge[2]["challenge"].as_string();

  // TODO: the secret needs to come from somewhere, and, will probably be salted.
  std::string key ="secret2";

  char digest[256];
  unsigned int digestlen = sizeof(digest)-1;
  memset(digest, 0, sizeof(digest));

  // TODO: check return value
  compute_HMACSHA256(key.c_str(), key.size(),
                     orig_challenge.c_str(), orig_challenge.size(),
                     digest, &digestlen,
                     HMACSHA256_BASE64);

  // the digest generated by the peer
  const std::string & peer_digest = ja[1].as_string();

  if (digest == peer_digest)
  {
    jalson::json_array msg;
    msg.push_back( WELCOME );
    msg.push_back( m_sid );

    send_msg( msg );

    if (m_state == eOpen) notify_session_state_change(true);
  }
  else
  {
    _WARN_("wamp_session CRA failed; expected '" << orig_challenge<< "', received '"<< peer_digest<<"'");

    jalson::json_array msg;
    msg.push_back( ABORT );
    msg.push_back( jalson::json_object() );
    msg.push_back( "wamp.error.authentication_failed" );
    send_msg( msg );
  }
}

//----------------------------------------------------------------------

/* In here have taken approach of doing the session open notification via the
 * event loop.  This sticks to the principle of minimising the actions tahken in
 * the IO thread. It can also be the start of a nice event model, because the
 * first event the event loop should see, for a session, is the session open
 * event.
 */
void wamp_session::notify_session_state_change(bool is_open)
{
  /* IO thread */    // <------ TODO?? doesn't need to be?

  if (m_notify_state_change_fn)
  {
    session_handle wp = handle();

    m_kernel.get_event_loop()->dispatch(
      [wp, is_open]()
      {
        if (auto sp = wp.lock())
          sp->m_notify_state_change_fn(wp, is_open);
      } );
  }
}

//----------------------------------------------------------------------

bool wamp_session::is_open() const
{
  return m_state == eOpen;
}

bool wamp_session::is_pending_open() const
{
  return (m_state != eOpen && m_state != eClosed && m_state != eClosing);
}

//----------------------------------------------------------------------

void wamp_session::initiate_handshake()
{
  /* IO thread */

  jalson::json_array msg;
  msg.push_back( HELLO );
  msg.push_back( m_realm );
  jalson::json_object& opt = jalson::append_object( msg );
  opt[ "roles" ] = jalson::json_object();
  opt[ "authid"] = "peter";
  opt[ "authmethods"] = jalson::json_array({"wampcra"});
  this->send_msg( msg );
}


int wamp_session::duration_since_last() const
{
  return (time(NULL) - m_time_last_msg_recv);
}


int wamp_session::duration_since_creation() const
{
  return (time(NULL) - m_time_create);
}


const std::string&  wamp_session::realm() const
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

  _INFO_("Sending REGISTER request for proc '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_registered(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: add more messsage checking here
  t_request_id request_id  = msg[1].as_uint();
  uint64_t registration_id = msg[2].as_uint();

  std::unique_lock<std::mutex> guard(m_pending_lock);
  auto iter = m_pending_register.find( request_id );

  if (iter != m_pending_register.end())
  {
    m_procedures[registration_id] = iter->second;
    m_pending_register.erase(iter);

    _INFO_("procedure '"<< m_procedures[registration_id].uri <<"' registered"
           << " with registration_id " << registration_id);
  }

}


void wamp_session::process_inbound_invocation(jalson::json_array & msg)
{
  /* EV thread */

  t_request_id request_id = msg[1].as_uint();
  uint64_t registration_id = msg[2].as_uint();

  // find the procedure
  try
  {
    auto iter = m_procedures.find(registration_id);

    if (iter == m_procedures.end())
      throw wamp_error(WAMP_ERROR_URI_NO_SUCH_REGISTRATION);

    wamp_args my_wamp_args;
    if ( msg.size() > 4 ) my_wamp_args.args_list = msg[4];
    if ( msg.size() > 5 ) my_wamp_args.args_dict = msg[5];

    std::string uri = iter->second.uri;

    invoke_details invoke;
    invoke.uri = iter->second.uri;
    invoke.user = iter->second.user_data;
    invoke.args = std::move(my_wamp_args);

    session_handle wp = this->handle();
    invoke.yield_fn = [wp,request_id](wamp_args args)
      {
        if (auto sp = wp.lock())
          sp->invocation_yield(request_id, std::move(args));
      };

    invoke.error_fn = [wp,request_id](wamp_args args, std::string error_uri)
      {
        if (auto sp = wp.lock())
          sp->reply_with_error(INVOCATION, request_id, std::move(args), std::move(error_uri));
      };

    {
      std::unique_lock<std::recursive_mutex> guard(m_user_cb_lock);
      if (m_user_cb_allowed) iter->second.user_cb(invoke);
    }

  }
  catch (XXX::wamp_error& ex)
  {
    reply_with_error(INVOCATION, request_id, ex.args(), ex.error_uri());
  }
  catch (std::exception& ex)
  {
    reply_with_error(INVOCATION, request_id, wamp_args(), WAMP_RUNTIME_ERROR);
  }
  catch (...)
  {
    reply_with_error(INVOCATION, request_id, wamp_args(), WAMP_RUNTIME_ERROR);
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

  _INFO_("Sending SUBSCRIBE request for topic '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_subscribed(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: add more messsage checking here
  t_request_id request_id  = msg[1].as_uint();
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
    _INFO_("Subscribed to topic '"<< temp.uri <<"'"
           << " with  subscription_id " << subscription_id);

    // user callback
    if (temp.user_cb)
      try
      {
        std::unique_lock<std::recursive_mutex> guard(m_user_cb_lock);
        if (m_user_cb_allowed)
          temp.user_cb(XXX::e_sub_start,
                       temp.uri,
                       jalson::json_object(),
                       jalson::json_array(),
                       jalson::json_object(),
                       temp.user_data);

      } catch(...){ log_exception(__logptr, "inbound subscribed user callback"); }

  }
}


void wamp_session::process_inbound_event(jalson::json_array & msg)
{
  /* EV thread */

  t_subscription_id subscription_id = msg[1].as_uint();
  jalson::json_object & details = msg.at(3).as_object();
  jalson::json_value * ptr_args_list = jalson::get_ptr(msg, 4); // optional
  jalson::json_value * ptr_args_dict = jalson::get_ptr(msg, 5); // optional

  const jalson::json_array  & args_list = ptr_args_list? ptr_args_list->as_array()  : jalson::json_array();
  const jalson::json_object & args_dict = ptr_args_dict? ptr_args_dict->as_object() : jalson::json_object();



  auto iter = m_subscriptions.find(subscription_id);
  if (iter !=m_subscriptions.end())
  {
    try {
      std::unique_lock<std::recursive_mutex> guard(m_user_cb_lock);
      if (m_user_cb_allowed)
        iter->second.user_cb(e_sub_update,
                             iter->second.uri,
                             details,
                             args_list,
                             args_dict,
                             iter->second.user_data);
    } catch (...){ log_exception(__logptr, "inbound event user callback"); }

  }
  else
  {
    _WARN_("Topic event ignored because subscription_id "
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
  if (!args.args_list.is_null()) msg.push_back( args.args_list );
  if (!args.args_dict.is_null()) msg.push_back( args.args_dict );

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

  _INFO_("Sending CALL request for  '" << uri << "', request_id " << request_id);
  return request_id;
}


void wamp_session::process_inbound_result(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: add more messsage checking here
  t_request_id request_id  = msg[1].as_uint();
  jalson::json_object & options = msg[2].as_object();

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
    if (orig_call.user_cb && m_user_cb_allowed)
    {
      wamp_call_result r;
      r.was_error = false;
      r.procedure = orig_call.rpc;
      r.user = orig_call.user_data;
      if (msg.size()>3) r.args.args_list  = std::move(msg[3]);
      if (msg.size()>4) r.args.args_dict  = msg[4];
      r.details = options;

      try {
        std::unique_lock<std::recursive_mutex> guard(m_user_cb_lock);
        if (m_user_cb_allowed) orig_call.user_cb(std::move(r));
      }
      catch(...){ log_exception(__logptr, "inbound result user callback"); }
    }
  }
  else
  {
    _WARN_("TODO: throw exception here");
  }

}

// TODO: split this into two error function, once for client role, other for active roll
void wamp_session::process_inbound_error(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: add more messsage checking here
  int request_type = msg[1].as_int();
  t_request_id request_id = msg[2].as_uint();
  jalson::json_object & details = msg[3].as_object();
  std::string& error_uri = msg[4].as_string();


  switch (request_type)
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

      std::cout << "TODO: here need to call the incoation reply_fn\n";
      wamp_args args;
      if ( msg.size() > 5 ) args.args_list = msg[5];
      if ( msg.size() > 6 ) args.args_dict = msg[6];
      std::unique_ptr<std::string> error_ptr( new std::string(error_uri) );

      try
      {
        orig_request.reply_fn(args, std::move(error_ptr));
      } catch (...){ log_exception(__logptr, "inbound invocation error user callback"); }

      break;
    }
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
        if (orig_call.user_cb && m_user_cb_allowed)
        {
          wamp_call_result r;
          r.was_error = true;
          r.error_uri = error_uri;
          r.procedure = orig_call.rpc;
          r.user = orig_call.user_data;
          // TODO: improve args handling
          r.args.args_list  = msg[5];
          r.details = details;

          try {
            std::unique_lock<std::recursive_mutex> guard(m_user_cb_lock);
            if (m_user_cb_allowed) orig_call.user_cb(std::move(r));
          }
          catch(...){ log_exception(__logptr, "inbound call error user callback");}
        }
      }
      else
      {
        _WARN_("TODO: handle protocol error");
      }

      break;
    }

    default:
    {
      _WARN_("TODO: handle error msg on unsupported type");
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
  if (!args.args_list.is_null())
  {
    msg.push_back( args.args_list );
    if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
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

  // TODO: any errors here, and we abort the connections, ie, its a bad message

  // TODO: add more messsage checking here
  t_request_id request_id = msg[1].as_uint();
  std::string& uri = msg[3].as_string();
  wamp_args my_wamp_args;
  if ( msg.size() > 4 ) my_wamp_args.args_list = msg[4];
  if ( msg.size() > 5 ) my_wamp_args.args_dict = msg[5];


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
          if (!args.args_list.is_null())
          {
            msg.push_back( args.args_list );
            if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
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
          if (!args.args_list.is_null())
          {
            msg.push_back( args.args_list );
            if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
          }
          sp->send_msg( msg );
        }
      }
    };

  m_server_handler.inbound_call(this, uri, std::move(my_wamp_args), std::move(reply_fn));
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
  if (!args.args_list.is_null())
  {
    msg.push_back( args.args_list );
    if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
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
  // TODO: add more messsage checking here
  t_request_id request_id = msg[1].as_uint();

  wamp_args args;
  if ( msg.size() > 3 ) args.args_list = msg[3];
  if ( msg.size() > 4 ) args.args_dict = msg[4];

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
    // TODO: add more messsage checking here
    jalson::json_string & uri = msg[3].as_string();
    wamp_args args;
    if ( msg.size() > 4 ) args.args_list = std::move(msg[4]);
    if ( msg.size() > 5 ) args.args_dict = std::move(msg[5]);

    m_server_handler.handle_inbound_publish(this, uri, args);
  }
}


void wamp_session::process_inbound_subscribe(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: any errors here, and we abort the connections, ie, its a bad message

  // TODO: add more messsage checking here
  t_request_id request_id = msg[1].as_uint();
  std::string uri = std::move( msg[3].as_string() );
  wamp_args my_wamp_args;
  if ( msg.size() > 4 ) my_wamp_args.args_list = msg[4];
  if ( msg.size() > 5 ) my_wamp_args.args_dict = msg[5];

  try
  {
    uint64_t subscription_id = m_server_handler.inbound_subscribe(this, uri, my_wamp_args);

    jalson::json_array out;
    out.push_back(SUBSCRIBED);
    out.push_back(request_id);
    out.push_back(subscription_id);
    send_msg(out);
  }
  catch(wamp_error ex)
  {
    reply_with_error(SUBSCRIBE, request_id, ex.args(), ex.error_uri());
  }
  catch (std::exception& ex)
  {
    reply_with_error(SUBSCRIBE, request_id, wamp_args(), ex.what());
  }
  catch (...)
  {
    reply_with_error(SUBSCRIBE, request_id, wamp_args(), WAMP_RUNTIME_ERROR);
  }
}


void wamp_session::process_inbound_register(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: add more messsage checking here
  t_request_id request_id = msg[1].as_uint();
  std::string uri = std::move(msg[3].as_string());

  try
  {
    uint64_t registration_id = m_server_handler.inbound_register(handle(),
                                                                 m_realm,
                                                                 std::move(uri));

    jalson::json_array resp;
    resp.push_back(REGISTERED);
    resp.push_back(request_id);
    resp.push_back(registration_id);
    send_msg(resp);
  }
  catch(wamp_error ex)
  {
    reply_with_error(REGISTER, request_id, ex.args(), ex.error_uri());
  }
  catch (std::exception& ex)
  {
    reply_with_error(REGISTER, request_id, wamp_args(), ex.what());
  }
  catch (...)
  {
    reply_with_error(REGISTER, request_id, wamp_args(), WAMP_RUNTIME_ERROR);
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

  if (!args.args_list.is_null())
  {
    msg.push_back(args.args_list);
    if (!args.args_dict.is_null()) msg.push_back(args.args_dict);
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

  if (!args.args_list.is_null())
  {
    msg.push_back(args.args_list);
    if (!args.args_dict.is_null()) msg.push_back(args.args_dict);
  }

  send_msg(msg);
}


bool wamp_session::uses_heartbeats() const
{
  return m_hb_intvl > 0;
}


void wamp_session::disable_callback()
{
  // ANY thread
  std::cout << "wamp_session::disable_callback\n";
  std::unique_lock<std::recursive_mutex> guard(m_user_cb_lock);
  m_user_cb_allowed = false;
}

} // namespace XXX
