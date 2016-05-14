#include "Session.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "WampTypes.h"
#include "event_loop.h"
#include "Logger.h"
#include "utils.h"

#include <jalson/jalson.h>

#include <memory>
#include <iomanip>

#include <string.h>
#include <unistd.h>


#define HEADERLEN 4 /* size of uint32 */
#define INBOUND_BUFFER_SIZE 2000 // TODO: increase


namespace XXX {

/* Constructor */
Session::Session(SID s,
                 Logger* logptr,
                 IOHandle* h,
                 event_loop & evl,
                 bool is_passive,
                 t_connection_id __user_conn_id,
                 std::string __realm)
  : m_state( eInit ),
    __logptr(logptr),
    m_handle( h ),
    m_hb_intvl(2),
    m_time_create(time(NULL)),
    m_time_last_msg(time(NULL)),
    m_next_request_id(1),
    m_buf( new char[ INBOUND_BUFFER_SIZE ] ),
    m_bytes_avail(0),
    m_is_closing(false),
    m_evl(evl),
    m_is_passive(is_passive),
    m_realm(__realm),
    m_session_handle(std::make_shared<t_sid>(s.unique_id())),
    m_user_conn_id(__user_conn_id)
{
  m_handle->set_listener(this);
}

//----------------------------------------------------------------------

/* Destructor */
Session::~Session()
{
  delete [] m_buf;
}

uint64_t Session::unique_id()
{
  return *m_session_handle;
}

//----------------------------------------------------------------------

void Session::close()
{
  std::lock_guard<std::mutex> guard(m_handle_lock);
  if (m_handle) m_handle->request_close();
}

//----------------------------------------------------------------------

void Session::on_close()
{
  /* IO thread */

  // following the call of this callback, we must not call the IO handle again
  {
    std::lock_guard<std::mutex> guard(m_handle_lock);
    m_handle = nullptr;
  }

  // perform all other notification on the event thread
  m_evl.push( [this]() {
      this->change_state(eClosed,eClosed);
    } );
}

//----------------------------------------------------------------------
void Session::on_read(char* src, size_t len)
{
  /* IO thread */

  std::string temp(src,len);
  std::cout << "recv: bytes " << len << ": " << temp << "\n";
  session_error se ( "", session_error::no_error );
  try
  {
    on_read_impl(src, len);
  }
  catch ( const session_error& e )
  {
    se = e;
    _ERROR_("session_error exception : " << e.what());
  }
  catch ( const std::exception& ev )
  {
    se.err = session_error::unknown;
    _ERROR_("exception : " << ev.what());
  }
  catch (...)
  {
    se.err = session_error::unknown;
  }

  if (se.err != session_error::no_error)
  {
    m_session_err = se.err;

    try
    {
      // TODO: this does not seem to get sent.  Probably the socket is getting
      // closed before the message is written.
      jalson::json_array msg;
      jalson::json_object error_dict;
      msg.push_back( GOODBYE );
      msg.push_back( jalson::json_object() );
      msg.push_back( se.uri );
      this->send_msg( msg );
    } catch (...){}


    m_is_closing = true;

    this->close();
  }

}


void Session::on_read_impl(char* src, size_t len)
{
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
            throw session_error(WAMP_RUNTIME_ERROR, "bad json message", session_error::bad_protocol);
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
      throw session_error(WAMP_RUNTIME_ERROR, "msg buffer full", session_error::msgbuf_full);
    }
  }
}
//----------------------------------------------------------------------

void Session::decode_and_process(char* ptr, size_t msglen)
{
  /* IO thread */

  bool must_close_session = false;
  std::string error_uri;
  std::string error_text;
  session_error::error_code my_session_error = session_error::unknown;

  try
  {
    jalson::json_value jv;
    jalson::decode(jv, ptr, msglen);

    // process on the EV thread
    std::function<void()> fn = [this,jv]() mutable
      {
        // TODO: need to handle exceptions from process_message
        this->process_message( jv );
      };
    m_evl.push(std::move(fn));

  }
  catch (const XXX::event_error& e)
  {
    // TODO: need to review handling of event_errors
    _DEBUG_( "Session::on_read_impl  event_error" );
    error_uri  = e.error_uri;
    must_close_session = e.is_fatal;
    error_text = e.what();
  }
  catch( const jalson::json_error& e)
  {
    throw session_error(WAMP_RUNTIME_ERROR, e.what(), session_error::bad_json);
  }

  if (must_close_session) throw my_session_error;
}

//----------------------------------------------------------------------

void Session::update_state_for_outbound(const jalson::json_array& msg)
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
      if (m_state != eOpen) this->close();
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
      if (m_state != eOpen) this->close();
    }
  }

}
//----------------------------------------------------------------------

void Session::change_state(SessionState expected, SessionState next)
{
  std::vector<std::string> names = {"eInit","eRecvHello","eSentChallenge",
                                    "eRecvAuth","eOpen","eClosed",
                                    "eSentHello","eRecvChallenge","eSentAuth" } ;

  if (next == eClosed && m_state != eClosed)
  {
    _INFO_("Session closed");
    m_state = eClosed;
    notify_session_state_change( false );
    return;
  }

  if (m_state == expected)
  {
    _INFO_("Session state: from " << names[m_state] << " to " << names[next]);
    m_state = next;
  }
  else
  {
    _ERROR_("Session state failure, cannot move from " << names[m_state] << " to " << names[next]);
  }

}

//----------------------------------------------------------------------

void Session::process_message(jalson::json_value&jv)
{
//  _DEBUG_( "recv msg: " <<  jv  << ", is_passive: " << m_is_passive);

  jalson::json_array & ja = jv.as_array();

  if (ja.size() == 0)
    throw session_error(WAMP_RUNTIME_ERROR, session_error::bad_protocol);

  int const message_type = jv.as_array()[0].as_int();

  m_time_last_msg = time(NULL);

  /* session state validation */

  // TODO: eventually I need to refactor this code to move all the dealer
  // specific or client specific, to it own location.
  bool fail_session = false;
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
      if (m_state != eOpen) this->close();
    }

    // New style
    switch (message_type)
    {
      case CALL :
        process_call(ja);
        return;

      case YIELD :
        process_yield(ja);
        return;

      case PUBLISH :
        process_publish(ja); // TODO: have an error handling specific to the kind of session (active/passive)
        return;

      case SUBSCRIBE :
        process_subscribe(ja);
        return;

      case REGISTER :
        process_register(ja);
        return;

      case ERROR :
        process_error(ja); // TODO: have an error handling specific to the kind of session (active/passive)
        return;
    }
  }
  else
  {
    /* session is for a client */
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
      if (m_state != eOpen) this->close();
    }

    // New style
    switch (message_type)
    {
      case REGISTERED :
        process_registered(ja);
        return;

      case INVOCATION :
        process_invocation(ja);
        return;

      case SUBSCRIBED :
        process_subscribed(ja);
        return;

      case EVENT :
        process_event(ja);
        return;

      case RESULT :
        process_result(ja);
        return;

      case ERROR :
        process_error(ja);  // TODO: have an error handling specific to the kind of session (active/passive)
        return;

    }
  }



  if (fail_session)
  {
    _ERROR_("session has been failed ... skipping message " << message_type);
    return;
  }


  // TODO: if here, could be an unsupported message type
}


void Session::send_request( int request_type,
                            unsigned int /*internal_req_id*/,
                            build_message_cb_v2 msg_builder )
{
  t_request_id request_id = m_next_request_id++;

  jalson::json_array req = msg_builder( request_id );

  this->send_msg( req );
}

//----------------------------------------------------------------------


void Session::send_msg(jalson::json_array& jv, bool final)
{
  if (!m_is_closing)
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

void Session::send_msg(build_message_cb_v4 builder)
{
  if (!m_is_closing)
  {

    jalson::json_array msg = builder();

    std::string str = jalson::encode(msg);

    update_state_for_outbound(msg);

    // write message length prefix
    std::pair<const char*, size_t> bufs[2];

    uint32_t msglen = htonl( str.size() );
    bufs[0].first  = (char*)&msglen;
    bufs[0].second = sizeof(msglen);

    // write message
    bufs[1].first  = (char*)str.c_str();
    bufs[1].second = str.size();
    this->send_bytes( &bufs[0], 2, false );
  }
}

//----------------------------------------------------------------------

bool Session::send_bytes(std::pair<const char*, size_t>* bufs, size_t count, bool final)
{
  /* EV thread */

  if (!m_is_closing)
  {
    std::lock_guard<std::mutex> guard(m_handle_lock);
    if (m_handle) m_handle->write_bufs(bufs, count, final);
  }
  return true;
}

//----------------------------------------------------------------------

// TODO: what happens if we throw in here, ie, we are on the Socket IO thread!!!!
void Session::handle_HELLO(jalson::json_array& ja)
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

  _INFO_("Session has received a session HELLO");
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
void Session::handle_CHALLENGE(jalson::json_array& ja)
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


void Session::handle_ABORT(jalson::json_array& /*ja*/)
{
  // TODO: prob need to escalate?
}

/*  Called on the IO thread when we have received a WELCOME message. This will
 *  indicate the the session is now open. Here we will be a client that is
 *  trying to logon to a remote service.
 */
void Session::handle_WELCOME(jalson::json_array& /*ja*/)
{

  /* */
  // TODO: prob need to escalate?
}

//----------------------------------------------------------------------

// TODO: what happens if we throw in here, ie, we are on the Socket IO thread!!!!
void Session::handle_AUTHENTICATE(jalson::json_array& ja)
{
  // TODO: could just store it in the Session ?

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
    t_sid sid = *m_session_handle;

    jalson::json_array msg;
    msg.push_back( WELCOME );
    msg.push_back( sid );

    send_msg( msg );

    if (m_state == eOpen) notify_session_state_change(true);
  }
  else
  {
    _WARN_("Session CRA failed; expected '" << orig_challenge<< "', received '"<< peer_digest<<"'");

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
void Session::notify_session_state_change(bool is_open)
{
  ev_session_state_event * e = new ev_session_state_event(is_open, m_session_err);
  e->src  = handle();
  e->user_conn_id = m_user_conn_id;
  m_evl.push( e );
}

//----------------------------------------------------------------------

bool Session::is_open() const
{
  return m_state == eOpen;
}

bool Session::is_pending_open() const
{
  return (m_state != eOpen && m_state != eClosed);
}

//----------------------------------------------------------------------

void Session::initiate_handshake()
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


int Session::duration_since_last() const
{
  return (time(NULL) - m_time_last_msg);
}

int Session::duration_pending_open() const
{
  if (is_open())
    return 0;
  else
    return (time(NULL) - m_time_create);
}

const std::string&  Session::realm() const
{
  // need this lock, because realm might be updated from IO thread during logon
  std::unique_lock<std::mutex> guard(m_realm_lock);
  return m_realm;
}


t_request_id Session::provide(std::string uri,
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

void Session::process_registered(jalson::json_array & msg)
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

void Session::process_invocation(jalson::json_array & msg)
{
  /* EV thread */

  // TODO: move this off the IO thread

  t_request_id request_id = msg[1].as_uint();
  uint64_t registration_id = msg[2].as_uint();


  // find the procedure
  auto iter = m_procedures.find(registration_id);
  if (iter != m_procedures.end())
  {
    wamp_args my_wamp_args;
    jalson::json_object & details = msg[3].as_object();
    if ( msg.size() > 4 ) my_wamp_args.args_list = msg[4];
    if ( msg.size() > 5 ) my_wamp_args.args_dict = msg[5];

    std::string uri = iter->second.uri;

    invoke_details invoke(request_id);
    session_handle src = handle();

    invoke.reply_fn = [this,request_id](t_request_id /*tid*/, wamp_args& args)
      {
        this->reply(request_id, args, false, "");
      };

    try
    {
      iter->second.user_cb(request_id,
                           invoke,
                           iter->second.uri,
                           details,
                           my_wamp_args,
                           src,
                           iter->second.user_data);
    }
    catch (XXX::invocation_exception& ex)
    {
      this->reply(request_id, ex.args(), true, ex.what());
    }
    catch (std::exception& ex)
    {
      wamp_args temp;
      this->reply(request_id, temp, true, ex.what());
    }
    catch (...)
    {
      wamp_args temp;
      this->reply(request_id, temp, true, WAMP_RUNTIME_ERROR);
    }
  }
  else
  {
    _INFO_("TODO: reply with WAMP_ERROR_URI_NO_SUCH_REGISTRATION");
  }
}


bool Session::reply(int request_id,
                    wamp_args& the_args,
                    bool is_error,
                    std::string error_uri)
{
  jalson::json_array msg;

  if (is_error)
  {
    msg.push_back(ERROR);
    msg.push_back(INVOCATION);
    msg.push_back(request_id);
    msg.push_back(jalson::json_object());
    msg.push_back(error_uri);
  }
  else
  {
    msg.push_back(YIELD);
    msg.push_back(request_id);
    msg.push_back(jalson::json_object());
  }

  if (!the_args.args_list.is_null()) msg.push_back(the_args.args_list);
  if (!the_args.args_dict.is_null()) msg.push_back(the_args.args_dict);

  send_msg(msg);
  return true;
}



t_request_id Session::subscribe(const std::string& uri,
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


void Session::process_subscribed(jalson::json_array & msg)
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
        temp.user_cb(XXX::e_sub_start,
                     temp.uri,
                     jalson::json_object(),
                     jalson::json_array(),
                     jalson::json_object(),
                     temp.user_data);
      } catch(...){}

  }
}


void Session::process_event(jalson::json_array & msg)
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
      iter->second.user_cb(e_sub_update,
                           iter->second.uri,
                           details,
                           args_list,
                           args_dict,
                           iter->second.user_data);
    } catch (...){}

  }
  else
  {
    _WARN_("Topic event ignored because subscription_id "
           << subscription_id << " not found");
  }
}


/* Initiate a CALL sequence */
t_request_id Session::call(std::string uri,
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


void Session::process_result(jalson::json_array & msg)
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
    }
    m_pending_call.erase(iter);
  }

  if (found)
  {
    if (orig_call.user_cb)
    {
      wamp_call_result r;
      r.was_error = false;
      r.procedure = orig_call.rpc;
      r.user = orig_call.user_data;
      if (msg.size()>3) r.args.args_list  = std::move(msg[3]);
      if (msg.size()>4) r.args.args_dict  = msg[4];
      r.details = options;

      try {
        orig_call.user_cb(std::move(r));
      }
      catch(...){}
    }
  }
  else
  {
    _WARN_("TODO: throw exception here");
  }

}


void Session::process_error(jalson::json_array & msg)
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
      bool found = false;

      {
        std::unique_lock<std::mutex> guard(m_pending_lock);
        auto iter = m_pending_invocation.find( request_id );
        if (iter != m_pending_invocation.end())
        {
          found = true;
          orig_request = std::move(iter->second);
          m_pending_invocation.erase(iter);
        }
      }

      std::cout << "TODO: here need to call the incoation reply_fn\n";
      wamp_args args;
      if ( msg.size() > 5 ) args.args_list = msg[5];
      if ( msg.size() > 6 ) args.args_dict = msg[6];
      std::unique_ptr<std::string> error_ptr( new std::string(error_uri) );
      orig_request.reply_fn(args, std::move(error_ptr));

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
        if (orig_call.user_cb)
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
            orig_call.user_cb(std::move(r));
          }
          catch(...){}
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


t_request_id Session::publish(std::string uri,
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


void Session::process_call(jalson::json_array & msg)
{
  std::cout << "Session::process_call" << "\n";
  /* EV thread */

  // TODO: add more messsage checking here
  t_request_id request_id = msg[1].as_uint();
  std::string& uri = msg[3].as_string();
  wamp_args my_wamp_args;
  if ( msg.size() > 4 ) my_wamp_args.args_list = msg[4];
  if ( msg.size() > 5 ) my_wamp_args.args_dict = msg[5];


  auto reply_fn = [this, request_id](wamp_args args, std::unique_ptr<std::string> error_uri){
    /* EV thread */
    // m_pending.erase(request_id);   <---- if that is found, ie, erase the function that allows for cancel
    // send a RESULT back to originator of the call

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
      send_msg( msg );
    }
    else
    {
      jalson::json_array msg;
      msg.push_back(ERROR);
      msg.push_back(CALL);
      msg.push_back(request_id);
      msg.push_back(jalson::json_object());
      msg.push_back(*error_uri);
      {
        msg.push_back( args.args_list );
        if (!args.args_dict.is_null()) msg.push_back( args.args_dict );
      }
      send_msg( msg );
    }
  };

  m_server_handler.handle_call(this, uri, msg, std::move(reply_fn));
}


void Session::set_server_handler(server_msg_handler h)
{
  m_server_handler = h;
}


t_request_id Session::invocation(uint64_t registration_id,
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


void Session::process_yield(jalson::json_array & msg)
{
  std::cout << __FUNCTION__ << "\n";

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
        _INFO_("yield --> calling invocation reply_fn");
        iter->second.reply_fn(args, nullptr);
      } catch (...){}
    }
    m_pending_invocation.erase(iter);
  }

}


void Session::process_publish(jalson::json_array & msg)
{
  /* EV thread */

  if (m_server_handler.handle_inbound_publish)
  {
    // TODO: add more messsage checking here
    jalson::json_string & uri = msg[3].as_string();
    // wamp_args args;
    // if ( msg.size() > 4 ) args.args_list = msg[4];
    // if ( msg.size() > 5 ) args.args_dict = msg[5];

    m_server_handler.handle_inbound_publish(this, uri, msg);
  }
}


void Session::process_subscribe(jalson::json_array & msg)
{
  /* EV thread */

  if (m_server_handler.inbound_subscribe)
  {
    m_server_handler.inbound_subscribe(this, msg);
  }
}

void Session::process_register(jalson::json_array & msg)
{
  // TODO: add more messsage checking here
  t_request_id request_id = msg[1].as_uint();
  std::string uri = std::move(msg[3].as_string());

  if (m_server_handler.inbound_register)
  {
    auto cb = [this,request_id](uint64_t registration_id)
      {
        jalson::json_array msg;
        msg.push_back(REGISTERED);
        msg.push_back(request_id);
        msg.push_back(registration_id);
        send_msg(msg);
      };

    m_server_handler.inbound_register(this, uri, std::move(cb));
  }

}


} // namespace XXX
