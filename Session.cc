#include "Session.h"

#include "IOHandle.h"
#include "SessionListener.h"
#include "TopicMan.h"
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


namespace XXX {


// TODO: I am still not sure of the best way to create the pending request
// structure. One the one hand, I could just stor ehte full messages, but then I
// think, do I need all those details on the reply?  Do we need to store the
// entire outbound message?  That concern has led me to come up with these
// pending structures, but the initial though that they could be jsut local to
// this class.  However, this cannot be the case now, because these structures
// need to go into the event loop etc, and used there.  So now we have a new set
// of data classes cropping up and being used all over the place.  So now I am
// going back to the json approach, just puting the entire output message into
// the pending queue.  Or perhaps this is not the right place ?  Maybe I need to
// have a request man, that anyone can interrogate?  ...... But, why do I need
// pending data for?  Well, yes, nice to have, for diagnoistics etc.  But one
// definite reason is to be able to store user data.  E.g., we have the cb_data
// field. E.g., at mimumum, will be the user-code callback to eventually call
// when a reply is received.
struct PendingReq
{
  int message_type;
  jalson::json_array request;
  Request_CB_Data * cb_data;

  PendingReq()
    : cb_data( nullptr )
  {
  }

  // NOTICE: have commented this out, because I am revieiwn approach to storing
  // callback objects.

  // virtual ~PendingReq()
  // {
  //   delete cb_data;
  // }
};



struct PendingCall : public PendingReq
{
  std::string procedure;
};


struct PendingRegister : public PendingReq
{
  std::string procedure;
};


/* Constructor */
Session::Session(SID s,
                 Logger* logptr,
                 IOHandle* h,
                 SessionListener * listener,
                 event_loop & evl,
                 bool is_passive,
                 t_connection_id __user_conn_id)
  : m_state( eInit ),
    __logptr(logptr),
    m_listener( listener ),
    m_handle( h ),
    m_hb_intvl(30),
    m_time_create(time(NULL)),
    m_opened(0),
    m_hb_last(0),
    m_request_id(0),
    m_buf( new char[65536] ), // TODO: make into to constant, and check during mempcy
    m_bytes_avail(0),
    m_is_closing(false),
    m_evl(evl),
    m_is_passive(is_passive),
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

  for (auto & item : m_pend_req) delete item.second;

}

//----------------------------------------------------------------------

void Session::close(int)
{
  // TODO: is this correct approach?
  //std::lock_guard<std::mutex> guard(m_handle_lock);
  //m_handle->active_close();
}

//----------------------------------------------------------------------

// TODO: try to make sure this gets called for all session close events
void Session::on_close(int)
{
  /* IO thread */

  // follow call of this callback, we must not call the IO handle again
  {
    std::lock_guard<std::mutex> guard(m_handle_lock);
    m_handle = nullptr;
  }

  change_state(eClosed,eClosed);
}

//----------------------------------------------------------------------

void Session::on_read(char* src, size_t len)
{
  try
  {
    on_read_impl(src, len);
  }
  catch ( event_error& ev )
  {
    _ERROR_("caught unexpection event error with Session");
  }
}

void Session::on_read_impl(char* src, size_t len)
{
  // TODO: improve efficiency!

  _DEBUG_("recv n:" << len);

  memcpy(m_buf + m_bytes_avail, src, len); // TODO: check length!
  m_bytes_avail += len;
  m_buf[m_bytes_avail] = '\0';  // TODO: need this while jalson cannot take data len

  char* ptr = m_buf;

  /* TODO: a problem that might occur here is that a bad message will be
   * recieved, like 'XXXX' for the length, and we will need to then wait until
   * we get that many bytes until we can move onto processing the message and
   * discovering it is a bad protocol. So need to beable to switch on some kind
   * of logging here. */

  bool had_error;
  bool must_close_session = false;
  std::string error_uri;
  std::string error_text;

  while (m_bytes_avail)
  {
    had_error = true;

    if (m_bytes_avail < HEADERLEN) break;
    uint32_t msglen =  ntohl( *((uint32_t*) ptr) );
    //_DEBUG_("msglen:" << msglen << ", m_bytes_avail:" << m_bytes_avail);

    try
    {
      if (m_bytes_avail < (HEADERLEN+msglen))
      {
        if (m_bytes_avail > HEADERLEN )
        {
          // take a peek at the first byte, see if it looks like a start of a JSON message
          char firstchar = *(ptr + HEADERLEN);
          if (firstchar != '[') throw event_error::runtime_fatal("bad protocol");
        }
        break;
      }

      /* we have enough bytes to decode */
      ptr += HEADERLEN;

      std::string temp(ptr,msglen);
      _DEBUG_("recv n:" << msglen << " data: " << temp);
      jalson::json_value jv = jalson::decode(ptr);

      this->process_message( jv );
      had_error = false;
    }
    catch (const XXX::event_error& e)
    {
      _DEBUG_( "Session::on_read_impl  event_error" );
      error_uri  = e.error_uri;
      must_close_session = e.is_fatal;
      error_text = e.what();
    }
    catch (const XXX::protocol_error& e)
    {
      _DEBUG_( "Session::on_read_impl  protocol_error" );
      error_uri = e.error_uri;
      must_close_session = e.close_session;
      error_text = e.what();
    }
    catch( const std::exception & e)
    {
      error_uri = WAMP_RUNTIME_ERROR;
      must_close_session = true;
      error_text = e.what();

      _ERROR_( "caught exception during message !!!! "<< e.what() );
    }
    catch( ... )
    {
      error_uri = WAMP_RUNTIME_ERROR;
      error_text = "unknown exception";
      must_close_session = true;
    }

    if (had_error)
    {
      jalson::json_array err;
      jalson::json_object error_dict;
      if ( !error_text.empty() ) error_dict[ "text" ] = error_text;
      err.push_back( ERROR );
      err.push_back( error_uri );
      err.push_back( error_dict );
      this->send_msg( err, true );
    }
    if (must_close_session)
    {
      _ERROR_( "TODO: need to figure out how to close thei session" );
      // TODO: how to gracefully close the session;
      // ALSO: now that we are closing, dont process next bytes

      m_is_closing = true;
      return;
    }

    // TODO: only terminate the seesion for protocol error or unknow wrror

    // TODO: if caught any kind of error, then want to terminate the session here.
    // TODO: how to we send a message, and, then enable it for closing?


    ptr += msglen;
    m_bytes_avail -= (HEADERLEN + msglen);
  }


  if (m_bytes_avail && (m_buf != ptr))
  {
    memmove(m_buf, ptr, m_bytes_avail);
    m_buf[m_bytes_avail] = '\0';  // TODO: need this while jalson cannot take data len
  }

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
      /* TODO: the session should be open for all other message types */

      if (m_state != eOpen)
      {
        _ERROR_("session is not open to send messages ... TODO: close the session here");
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
      /* TODO: the session should be open for all other message types */
      if (m_state != eOpen)
      {
        _ERROR_("session is not open to send messages ... TODO: close the session here");
      }
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
  _DEBUG_( "recv msg: " <<  jv  << ", is_passive: " << m_is_passive);

  // TODO: need basic WAMP checking here

  jalson::json_array ja = jv.as_array();  // TODO: raise a protocol error if fails

  if (!jv.as_array()[0].is_number()) return; // TODO: add better error handling

  int const message_type = jv.as_array()[0].as_sint();


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
      _INFO_("recv ABORT from peer");
      change_state(eClosed, eClosed);
      handle_ABORT(ja);
      return;
    }
    else
    {
      /* TODO: check state is open */
      if (m_state != eOpen)
      {
        _ERROR_("session is not open to receive messages ... TODO: close the session here");
      }
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
      /* TODO: check state is open */
      if (m_state != eOpen)
      {
        _ERROR_("session is not open to receive messages ... TODO: close the session here");
      }
    }
  }


  if (fail_session)
  {
    _ERROR_("session has been failed ... skipping message " << message_type);
    return;
  }


  PendingReq * pendreq = nullptr;
  PendingReq2 pend2;

  /* A subset of WAMP message types are classified as Responses, ie, the match
   * up to Request class messages that would have been earlier sent out.  Here
   * we try to match up a received response to its earlier request.  */
  switch(message_type)
  {
    case YIELD :
    {
      int const request_id = jv.as_array()[1].as_uint();
      {
        // TODO: need to delete from the map
        std::lock_guard<std::mutex> guard(m_pend_req_lock);
        pendreq = m_pend_req[request_id];
        m_pend_req[request_id] = 0;
        pend2 = m_pend_req_2[request_id];  // TODO: and remove?
      }
      break;
    }
    case REGISTERED :
    {
      int const request_id = jv.as_array()[1].as_uint();
      {
        // TODO: need to delete from the map
        std::lock_guard<std::mutex> guard(m_pend_req_lock);
        pendreq = m_pend_req[request_id];
        m_pend_req[request_id] = 0;
        pend2 = m_pend_req_2[request_id]; // TODO: and remove?
      }
      break;
    }
    case ERROR :
    {
      int const request_id = jv.as_array()[2].as_uint();
      {
        // TODO: need to delete from the map
        std::lock_guard<std::mutex> guard(m_pend_req_lock);
        pendreq = m_pend_req[request_id];
        m_pend_req[request_id] = 0;
        pend2 = m_pend_req_2[request_id]; // TODO: and remove?
      }
      _INFO_( "got ERROR for request_id: " << request_id
              << ", pendreq:" << pendreq );
      break;
    }
    case RESULT :
    {
      int const request_id = jv.as_array()[1].as_uint();
      {
        // TODO: need to delete from the map
        std::lock_guard<std::mutex> guard(m_pend_req_lock);
        pendreq = m_pend_req[request_id];
        m_pend_req[request_id] = 0;
        pend2 = m_pend_req_2[request_id]; // TODO: and remove?
      }
      break;
    }

    case SUBSCRIBED:
    {
      int const request_id = jv.as_array()[1].as_uint();
      {
        // TODO: need to delete from the map
        std::lock_guard<std::mutex> guard(m_pend_req_lock);
        pendreq = m_pend_req[request_id];
        m_pend_req[request_id] = 0;
        pend2 = m_pend_req_2[request_id];  // TODO: and remove?
      }

      ev_inbound_subscribed* ev = new ev_inbound_subscribed();
      ev->src = handle();
      ev->user_conn_id = m_user_conn_id;
      ev->ja = ja;
      ev->internal_req_id  = pend2.internal_req_id;
      m_evl.push( ev );
      delete pendreq;
      return;
    }

  }

/*
  NEXT: extract the request id, get the message, remove the request, and get the
    json message and add it to the event. Meanwhile make a note to think about
    if this is the correct approach.  E.g. alter approach is to have a pending
    man, who can be interrogated from anywhere.  */

  // TODO: this is the generic message handling. Ie defer everything to the
  // event loop.  Although, there will be some stuff we need to handle at the
  // session layer.

  // new style, using a dedicated event class for inbound messages
  ev_inbound_message * ev = new ev_inbound_message(message_type);
  ev->src = handle();
  ev->user_conn_id = m_user_conn_id;
  ev->ja = ja;
  if (pendreq) ev->cb_data  = pendreq->cb_data;
  ev->internal_req_id  = pend2.internal_req_id;
  ev->user = pend2.user;
  m_evl.push( ev );

  // TODO: arrrgh. Cannot use this delete here, because it currently seems to
  // also delete the internal pointer the CB object, which there causes a core
  // dumpo in client_service::handle_REGISTERED during the dynamic_cast.
  // Update: have put it back in now, because I might try to move to the new
  // style, where I use an internal request ID.
  delete pendreq;
}

//----------------------------------------------------------------------

void Session::remove_listener()
{
  m_listener = nullptr;
}


void Session::call( const std::string& procedure )
{
  // NOTE: this needs to be locked, so that obaining an ID, and the send, are
  // the same atomic operation ... or, can we be sure it will only by the event
  // loop thread coming in here?

  uint64_t request_id = ++m_request_id; // TODO: needs to be atomic

  PendingCall * pending = new PendingCall() ;
  pending->message_type = CALL;
  pending->procedure = procedure;

  {
    std::lock_guard<std::mutex> guard(m_pend_req_lock);
    m_pend_req[request_id] = pending;
  }

  // [CALL, Request|id, Options|dict, Procedure|uri, Arguments|list, ArgumentsKw|dict]
  jalson::json_array json;
  json.push_back(CALL);
  json.push_back(request_id);
  json.push_back( jalson::json_object() );
  json.push_back( procedure );
  json.push_back( jalson::json_array() );
  json.push_back( jalson::json_object() );

  pending->request = json;

  this->send_msg( json );

  // TODO: set up a response handle
}


void Session::send_request( int request_type,
                            unsigned int internal_req_id,
                            build_message_cb_v2 msg_builder )
{
  _INFO_("Session::send_request internal_req_id=" << internal_req_id);
  uint64_t request_id = ++m_request_id; // TODO: needs to be atomic

  // TODO: here I am using the PendingRegister struct ... but question is, do I
  // need a request-specific structure, or, can I have something generic?
  PendingRegister * pending = new PendingRegister();  // TODO: memleak

  pending->message_type = request_type;

  {
    std::lock_guard<std::mutex> guard(m_pend_req_lock);
    m_pend_req[request_id] = pending;
  }

  std::pair< jalson::json_array, Request_CB_Data*> req
    = msg_builder( request_id );

  pending->request = req.first;
  pending->cb_data = req.second;

  PendingReq2 pend2;
  pend2.request_type = request_type;
  pend2.external_req_id = request_id;
  pend2.internal_req_id = internal_req_id;
  m_pend_req_2[ request_id ] = pend2;

  this->send_msg( req.first );
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
  session_state_event * e = new session_state_event(is_open);
  e->src  = handle();
  e->user_conn_id = m_user_conn_id;
  m_evl.push( e );
}

//----------------------------------------------------------------------

bool Session::is_open() const
{
  return m_state == eOpen;
}

//----------------------------------------------------------------------

void Session::initiate_handshake()
{
  /* IO thread */

  jalson::json_array msg;
  msg.push_back( HELLO );
  msg.push_back( "the_realm" );
  jalson::json_object& opt = jalson::append_object( msg );
  opt[ "roles" ] = jalson::json_object();
  opt[ "authid"] = "peter";
  opt[ "authmethods"] = jalson::json_array({"wampcra"});
  this->send_msg( msg );
}


int Session::duration_pending_open() const
{
  if (is_open())
    return 0;
  else
    return (time(NULL) - m_time_create)*1000;
}


} // namespace XXX
