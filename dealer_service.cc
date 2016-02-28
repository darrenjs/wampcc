#include "dealer_service.h"

#include "IOHandle.h"
#include "rpc_man.h"
#include "event.h"
#include "Logger.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "SessionMan.h"

#include <unistd.h>
#include <string.h>

namespace XXX {

// struct dealer_service::Connection
// {
//   uv_tcp_t uv_tcp_handle;
//   Session * session;
//   dealer_service * owner;
//   dealer_service::Request request;
// };

// /* Called on the IO thread when a connection attempt has completed */
// static void __on_connect(uv_connect_t* __req, int status )
// {
//   std::unique_ptr<uv_connect_t> connect_req(__req); // auto deleter

//   dealer_service::Connection * connection = (dealer_service::Connection *) connect_req->data;

//   if (status < 0)
//   {
//     fprintf(stderr, "connect error %s\n", uv_strerror(status));
//     if (connection->request.cb)
//       connection->request.cb( 0, status);
//   }
//   else
//   {
//     // IOLoop has set itself as the uv_loop data member
//     IOLoop * myIOLoop = static_cast<IOLoop* >(__req->handle->loop->data);

//     IOHandle* iohandle  = new IOHandle(  (uv_stream_t *) &connection->uv_tcp_handle,
//                                          myIOLoop,
//                                          0);

//    Session* sptr = connection->owner->new_client( iohandle );

//     // TODO: put this back in!!!
//     //connection->session = new Session(SID(), iohandle, nullptr, nullptr, nullptr, temp_evl);

//     if (connection->request.cb)
//       connection->request.cb( sptr, 0);
//   }

// }

// static void __io_on_timer(uv_timer_t* handle)
// {
//   dealer_service* p = (dealer_service*) handle->data;
//   try
//   {
//     p->on_timer();
//   }
//   catch(...)
//   {
//     // TODO: add logging
//   }
//}

dealer_service::dealer_service(Logger *logptr,
                               dealer_listener* l)
  : __logptr( logptr ),
    m_io_loop( new IOLoop( logptr,
                           [this](){this->on_io_timer();},
                           [this](){this->on_io_async();} )),
    m_evl( new event_loop( logptr ) ),
  m_sesman( new SessionMan(logptr, *m_evl.get()) ),
  m_rpcman( new rpc_man(logptr, *m_evl.get(), [this](const rpc_details*r){this->rpc_registered_cb(r); }) ),
    m_listener( l ),
    m_next_internal_request_id(1)
{
  m_evl->set_session_man( m_sesman.get() );
  m_evl->set_rpc_man( m_rpcman.get() );

  m_evl->set_handler(YIELD,
                    [this](class event* ev){ this->handle_YIELD(ev); } );


  m_io_loop->m_new_client_cb = [this](IOHandle *h,
                                      int  status,
                                      tcp_connect_attempt_cb user_cb,
                                      void* user_data)
    {

      /* === Called on IO thread === */
      tcp_connect_event * ev = new tcp_connect_event(user_cb, user_data, status);
      if (h)
      {
        Session* sptr = m_sesman -> create_session(h, true);
        ev->src = sptr->handle();
      }
      m_evl->push( ev );
    };
}

dealer_service::~dealer_service()
{
  m_io_loop->stop();
}
//----------------------------------------------------------------------


void dealer_service::start()
{

  // NOTE:  not using idler anymore, because it causes 100% CPU
  // uv_idle_t idler;
  // uv_idle_init(loop, &idler);
  // uv_idle_start(&idler, io_on_idle);



  // uv_timer_t timer_req;  // TODO: should be a member?
  // uv_timer_init(loop, &timer_req);
  // timer_req.data = this;
  // uv_timer_start(&timer_req, __io_on_timer, 30000, 30000);


  // // Create a tcp socket, and configure for listen
  // uv_tcp_t server; // TODO: what if this goes out of scope?
  // uv_tcp_init(loop, &server);
  // server.data = this;

  // struct sockaddr_in addr;
  // uv_ip4_addr("0.0.0.0", 55555, &addr);

  // unsigned flags = 0;
  // uv_tcp_bind(&server, (const struct sockaddr*)&addr, flags);
  // int r = uv_listen((uv_stream_t *) &server, 5, __on_tcp_connect);
  // std::cout << "loop starting, r="<< r << "\n";

  // start the IOLoop thread; returns immediately
  m_io_loop->start();
}

/* Called on the IO thread, and is the only place we can interact with IO
 * related data structures. */
void dealer_service::on_io_async()
{
  _DEBUG_( __FUNCTION__ );

  // decltype( m_connect_requests ) tmp;
  // {
  //   std::lock_guard<std::mutex> guard( m_connect_requests_lock );
  //   tmp.swap( m_connect_requests );
  // }

  // for (auto & req : tmp)
  // {
  //   std::unique_ptr<Connection> handle ( new Connection() );
  //   uv_tcp_init(m_io_loop.uv_loop(), &handle->uv_tcp_handle);
  //   handle->request = req;
  //   handle->owner = this;


  //   // use C++ allocator, so that I can vanilla unique_ptr
  //   uv_connect_t * connect_req = new uv_connect_t();
  //   connect_req->data = handle.get();

  //   struct sockaddr_in dest;
  //   uv_ip4_addr(req.addr.c_str(), req.port, &dest);

  //   _INFO_("making TCP connection to " << req.addr.c_str() <<  ":" << req.port);
  //   int r = uv_tcp_connect(connect_req,
  //                          &handle->uv_tcp_handle,
  //                          (const struct sockaddr*)&dest,
  //                          __on_connect);

  //   if (!r)
  //   {
  //     // TODO : return this error on the IO thread, eg we get an immediate error
  //     // if we try to connect to 227.43.0.1 although, I think it is better to
  //     // return it immediately.
  //     //_INFO_ ("r=" << r );
  //   }

  //   {
  //     std::lock_guard<std::mutex> guard( m_handles_lock );
  //     m_handles.push_back(handle.get());
  //     handle.release();
  //   }
  // }

};

// TODO: the whole connector business should be in a separate object
void dealer_service::connect(const std::string & addr,
                             int port,
                             tcp_connect_attempt_cb user_cb,
                             void* user_data)
{
  m_io_loop->add_connection(addr,
                           port,
                           user_cb,
                           user_data);
}


/* This is the special interface on the dealer_service API which allows CALL
 * sequences to be triggered by the API client, rather than a traditiona WAMP
 * client (ie, TCP based).  The callback is the entry point into the user code
 * when a YIELD or ERROR is received.
 */
unsigned int dealer_service::call_rpc(std::string rpc,
                                      call_user_cb cb,
                                      rpc_args args,
                                      void* cb_user_data)
{
  /* USER-THREAD */

  unsigned int int_req_id = m_next_internal_request_id++;

  {
    std::lock_guard<std::mutex> guard( m_pending_requests_lock );
    auto & pending = m_pending_requests[int_req_id];
    pending.cb = cb;
    pending.user_cb_data = cb_user_data;
  }

  outbound_call_event * ev = new outbound_call_event();

  ev->mode = event::eOutbound;
  ev->msg_type = CALL;
  ev->rpc_name= rpc;
  ev->cb = cb;  // memleak?
  ev->args = args; // memleak?
  ev->cb_user_data = cb_user_data;
  ev->internal_req_id=int_req_id;

  m_evl->push( ev );


  return int_req_id;
}

// void dealer_service::handle_HELLO(event* ev)
// {

//   /* WAMP:

//      [ (0) "HELLO",
//        (1) "realm1",
//        (2) {
//             "roles": {},
//             "authid": "peter",
//             "authmethods": ["wampcra"]
//            }
//      ]
//   */

//   _INFO_("Session has received a session HELLO");
// //  m_auth.recvHello = true;
// //  m_auth.hello_realm = msum.msg->at(1).as_string();
// //  m_auth.hello_opts  = msum.msg->at(2).as_object();

//   // m_sid = m_auth.hello_opts["authid"].as_string().value();
//   // m_sid = m_auth.hello_opts["agentid"].as_string().value();

//   const jalson::json_object & authopts = ev->ja.at(2).as_object();

//   /* TODO: verify the realm */

//   // Realm* realm = m_sessman->getRealm(m_auth.hello_realm);
//   // if ( realm == NULL)
//   // {
//   //   _ERROR_("Rejecting HELLO for unknown realm [" << m_auth.hello_realm << "]");
//   //   // TODO: abort
//   //   abort_authentication("authentication failed",
//   //                        "wamp.error.no_such_realm");
//   //   return;
//   // }

//   /* verify the user */

//   // get the user id
//   std::string authid = jalson::get_or_throw(authopts, "authid").as_string();

//   _INFO_("HELLO: authid=" << authid);

//   /* verify the supported auth methods */

//   // look for the "wampcra"
//   bool wampcra_found = false;
//   const jalson::json_array& methods = jalson::get_or_throw(authopts,"authmethods").as_array();
//   for (size_t i = 0; i < methods.size() && !wampcra_found; ++i)
//   {
//     if ( methods[i].is_string() )
//     {
//       std::string str = methods[i].as_string();
//       if (str == "wampcra") wampcra_found = true;
//     }
//   }

//   if (wampcra_found)
//   {
//     _INFO_("HELLO: wampcra=" << wampcra_found);
//   }
//   else
//   {
//     // TODO: need to abort the session
//   }


//   /* Construct the challenge */

//   // TODO: next, we need issue a challenge to the peer

//   // TODO: need to serialise this object.  This is mandated by the WAMP spec.
//   jalson::json_object challenge;
//   challenge["nonce"] = "LHRTC9zeOIrt_9U3";
//   challenge["authprovider"] = "userdb";
//   challenge["authid"] = "peter";
//   challenge["timestamp"] = "2014-06-22T16:36:25.448Z";
//   challenge["authrole"] = "user";
//   challenge["authmethod"] = "wampcra";
//   challenge["session"] = "3251278072152162";
//   std::string challengestr = jalson::encode( challenge );

//   /*
//       [  CHALLENGE,
//          AuthMethod|string,
//          Extra|dict]
//   */
//   jalson::json_array msg;
//   msg.push_back( CHALLENGE );
//   msg.push_back( "wampcra" );
//   jalson::append_object(msg)["challenge"] = challengestr;

//   outbound_message * outev = new outbound_message();
//   outev->destination = ev->src;
//   outev->message_type = CHALLENGE;
//   outev->ja = msg;

//   // TODO: why is this going via the EVL?
//   m_evl.push( outev );
// }

//----------------------------------------------------------------------

void dealer_service::rpc_registered_cb(const rpc_details* ev)
{
  if (m_listener) m_listener->rpc_registered( ev->uri );
}

//----------------------------------------------------------------------


// TODO: this can be generated from teh EVL thread, via a timeout on the wait.
void dealer_service::on_io_timer()
{
  /* IO-THREAD */
  event  * ev = new event(event::house_keeping);
  m_evl->push( ev );
}

//----------------------------------------------------------------------

void dealer_service::handle_YIELD(event* ev)
{
  unsigned int internal_req_id = ev->internal_req_id;
//  void * user = ev->user;

  pending_request pend ;

  {
    std::lock_guard<std::mutex> guard( m_pending_requests_lock );
    pend = m_pending_requests[internal_req_id];
  }

  call_info info;
  info.reqid = ev->ja[1].as_uint();
  info.procedure = pend.procedure;

  rpc_args args;
  args.args    = ev->ja[3]; // dont care about the type
  args.options = ev->ja[2].as_object();  // TODO: need to pre-verify the message


  // TODO: catch and log exception
  if ( pend.cb )
  {
    try
    {
      pend.cb(info, args, pend.user_cb_data);
    }
    // TODO: try to print
    catch (...)
    {
      _WARN_("exception during user callback");
    }

  }
  else
  {
    _WARN_("no callback function to handle request response");
  }

}



} // namespace
