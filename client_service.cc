#include "client_service.h"

#include "IOHandle.h"
#include "SessionMan.h"
#include "Session.h"
#include "WampTypes.h"
#include "Logger.h"
#include "utils.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"

#include <iostream>

#include <unistd.h>
#include <string.h>


namespace XXX {



struct Request_Register_CD_Data : public Request_CB_Data
{
  std::string procedure;
};


bool client_service::RegistrationKey::operator<(const RegistrationKey& rhs) const
{
  return ( (this->s < rhs.s) or ((this->s == rhs.s) and (this->id < rhs.id) ) );
}

//----------------------------------------------------------------------

/* Constructor */
client_service::client_service(Logger * logptr,
                               config config)
  : __logptr( logptr),
    m_config( config ),
    m_io_loop( new IOLoop( logptr,
                           [this](){this->on_io_timer(); },
                           [this](){this->on_io_async(); } ) ),
    m_evl( new event_loop(logptr) ),
    m_sesman(new SessionMan(__logptr, *m_evl.get()))
{
  m_evl->set_session_man( m_sesman.get() );

  m_sesman->set_session_event_listener(
    [this](Session* s, bool b){this->handle_session_state_change(s,b);});

  // m_evl.set_handler(CHALLENGE,
  //                   [this](class event* ev){ this->handle_CHALLENGE(ev); } );

  m_evl->set_handler(REGISTERED,
                    [this](class event* ev){ this->handle_REGISTERED(ev); } );

  m_evl->set_handler(INVOCATION,
                    [this](class event* ev){ this->handle_INVOCATION(ev); } );

  m_io_loop->m_new_client_cb = [this](IOHandle* h, int /* status*/ ,tcp_connect_attempt_cb, void*){this->new_client(h);};
}

//----------------------------------------------------------------------

/* Destructor */
client_service::~client_service()
{
  m_io_loop->stop();
}

void client_service::handle_session_state_change(Session* sptr, bool is_open)
{
  if (is_open == false) return;

  _INFO_("session is now ready ... registering procedures");


  // TODO: this must come only after we have been authenticated
  // register our procedures
  {
    std::lock_guard< std::mutex > guard ( m_procedures_lock );

    for (auto i : m_procedures)
    {
      const std::string & procedure = i.first;

      build_message_cb_v2 msg_builder2 = [&procedure](int request_id)
        {
          /* WAMP spec.
             [
             INVOCATION,
             Request|id,
             REGISTERED.Registration|id,
             Details|dict
             CALL.Arguments|list,
             CALL.ArgumentsKw|dict
             ]
          */


          jalson::json_array msg;
          msg.push_back( REGISTER );
          msg.push_back( request_id );
          msg.push_back( jalson::json_object() );
          msg.push_back( procedure  );

          Request_Register_CD_Data * cb_data = new Request_Register_CD_Data(); // TODO: memleak?
          cb_data->procedure = procedure;

          // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
          return std::pair< jalson::json_array, Request_CB_Data*> ( msg,
                                                                    cb_data );

        };

      // TODO: instead of 0, need to have a valie intenral request id
      m_sesman->send_request( sptr->sid(), REGISTER, 0, msg_builder2);
    }
  }


}

//----------------------------------------------------------------------

void client_service::new_client(IOHandle * iohandle)
{
  /* === Called on IO thread === */

  // creating a session ... from a passive connections
  Session* sptr = m_sesman -> create_session(iohandle, false);

  std::string the_realm="default";

  // TODO: probably want to move this into the Session
  {
    jalson::json_array msg;
    msg.push_back( HELLO );
    msg.push_back( the_realm );
    jalson::json_object& opt = jalson::append_object( msg );
    opt[ "roles" ] = jalson::json_object();
    opt[ "authid"] = "peter";
    opt[ "authmethods"] = jalson::json_array({"wampcra"});
    sptr->send_msg( msg );
  }


}

//----------------------------------------------------------------------

void client_service::start()
{
  // NOTE:  not using idler anymore, because it causes 100% CPU.  But add to uv notes.
  // uv_idle_t idler;
  // uv_idle_init(loop, &idler);
  // uv_idle_start(&idler, io_on_idle);


  // start the IOLoop thread; returns immediately
  m_io_loop->start();

  if (m_config.port )
    m_io_loop->add_server( m_config.port );
}

//----------------------------------------------------------------------

/* Called on the IO thread, and is the only place we can interact with IO
 * related data structures. */
void client_service::on_io_async()
{
  std::cout << __FUNCTION__ << "\n";
  // decltype( m_requests ) tmp;
  // {
  //   std::lock_guard<std::mutex> guard( m_requests_lock );
  //   tmp.swap(m_requests);
  // }

  // for (auto & req : tmp)
  // {
  //   std::unique_ptr<Connection> handle ( new Connection() );
  //   uv_tcp_init(&m_loop->m_uv_loop, &handle->uv_tcp_handle);
  //   handle->request = req;
  //   handle->owner = this;

  //   uv_tcp_t tcp_handle;
  //   uv_tcp_init(&m_loop->m_uv_loop, &tcp_handle);

  //   uv_connect_t * connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
  //   connect_req->data = handle.get();

  //   struct sockaddr_in dest;
  //   uv_ip4_addr(req.addr.c_str(), req.port, &dest);

  //   int r = uv_tcp_connect(connect_req,
  //                          &handle->uv_tcp_handle,
  //                          (const struct sockaddr*)&dest,
  //                          __on_connect);

  //   if (!r)
  //   {
  //     // TODO : return this error on the IO thread, eg we get an immediate error
  //     // if we try to connect to 227.43.0.1 although, I think it is better to
  //     // return it immediately.
  //     std::cout << "r=" << r << "\n";
  //   }

  //   {
  //     std::lock_guard<std::mutex> guard( m_handles_lock );
  //     m_handles.push_back(handle.get());
  //     handle.release();
  //   }
  // }
}

void client_service::add_procedure(const std::string& uri,
                                   rpc_cb cb,
                                   void * data)
{
  // TODO: refuse to allow duplicate, ie, throw or something?

  std::lock_guard< std::mutex > guard ( m_procedures_lock );
  auto it = m_procedures.find( uri );
  if (it == m_procedures.end())
  {
    m_procedures[ uri ] = std::make_pair(cb, data);
  }
}

//----------------------------------------------------------------------

void client_service::handle_REGISTERED(event* ev)
{
  Request_Register_CD_Data* cb_data = nullptr;

  if (ev && ev->cb_data)
  {
    cb_data = dynamic_cast<Request_Register_CD_Data*>(ev->cb_data); // DJS, core here
  }

  if (cb_data)
  {

    // TODO: check, what type does WAMP allow here?
    int registration_id = ev->ja[2].as_sint();

    RegistrationKey key;
    key.s  = ev->src;
    key.id = registration_id;


    // OKAY: when I sent a REGISTER request, I did not store the REQUEST ID
    // anywhere, did I ? So I need to find that request, and store it.  Wheere is
    // the best place to store it?
    {
      std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
      m_registrationid_map[ key ] = cb_data->procedure;
    }
    _INFO_("procedure '" << cb_data->procedure << "' registered with key "
           << key.s << ":" << key.id);
  }
  else
  {
    _ERROR_( "ERROR: failed to process end-point registered message");
  }
}

//----------------------------------------------------------------------

void client_service::handle_INVOCATION(event* ev) // change to lowercase
{
  // TODO: need to parse the INVOCATION message here, eg, check it is valid
  RegistrationKey rkey;
  rkey.s  = ev->src;
  rkey.id = ev->ja[2].as_sint();

  std::string procedurename;
  {
    std::unique_lock<std::mutex> guard(m_registrationid_map_lock);
    auto it = m_registrationid_map.find(rkey);

    // for (auto i : m_registrationid_map)
    // {
    //   std::cout << "key " << i.first << "\n";
    // }

    if (it == m_registrationid_map.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       ev->ja[1].as_sint());
    }
    procedurename = it->second;
  }

  std::pair< rpc_cb,void*> rpc_actual;
  {
    std::unique_lock<std::mutex> guard(m_procedures_lock);
    auto it = m_procedures.find( procedurename );

    if (it == m_procedures.end())
    {
      throw event_error::request_error(WAMP_URI_NO_SUCH_REGISTRATION,
                                       INVOCATION,
                                       ev->ja[1].as_sint());
    }
    rpc_actual = it->second;
  }

  _INFO_( "invoke lookup success, key " << rkey.s <<":"<<rkey.id  << " -> " << procedurename );

  rpc_args my_rpc_args;
  if ( ev->ja.size() > 4 ) my_rpc_args.args = ev->ja[ 4 ];

  t_request_id reqid = ev->ja[1].as_sint(); // TODO: make a helper for this, ie, json to t_requetst_id

  // TODO: need to think about whole business of catching exceptions here.
  // Well, the pattern is, any exception/error that occurs just up until the
  // user cb should be handled and result in an ERROR being send back as a
  // response to the inbound request.
  if (rpc_actual.first)
  {
    rpc_actual.first(*this, rkey.s.unique_id(), procedurename, reqid, my_rpc_args, rpc_actual.second);
  }

  return;
}

//----------------------------------------------------------------------

void client_service::post_reply(t_sid sid,
                                t_request_id reqid,
                                rpc_args& the_args)
{
  /* user thread or EVL thread */

  outbound_response_event* ev = new outbound_response_event();

  ev->destination   = SID( sid );
  ev->response_type = YIELD;
  ev->request_type  = INVOCATION;
  ev->reqid         = reqid;
  ev->args          = the_args;

  m_evl->push( ev );
}

//----------------------------------------------------------------------

void client_service::post_error(t_sid sid,
                                t_request_id reqid,
                                std::string& error_uri)
{
  /* user thread or EVL thread */

  outbound_response_event* ev = new outbound_response_event();

  ev->destination   = SID( sid );
  ev->response_type = ERROR;
  ev->request_type  = INVOCATION;
  ev->reqid         = reqid;
  ev->error_uri     = error_uri;

  m_evl->push( ev );
}


// TODO: this can be generated from teh EVL thread, via a timeout on the wait.
void client_service::on_io_timer()
{
  /* IO-THREAD */
  event  * ev = new event(event::house_keeping);
  m_evl->push( ev );
}

} // namespace XXX
