#include "client_service.h"

#include "IOHandle.h"
#include "Session.h"
#include "Logger.h"
#include "utils.h"
#include "IOLoop.h"
#include "event_loop.h"
#include "Topic.h"

#include <iostream>

#include <unistd.h>
#include <string.h>


namespace XXX {


//----------------------------------------------------------------------


/* Constructor */
client_service::client_service(Logger * logptr)
  : __logptr( logptr),
    m_io_loop( new IOLoop(logptr) ),
    m_evl( new event_loop(logptr) )
{
}

//----------------------------------------------------------------------

/* Destructor */
client_service::~client_service()
{
  // TODO: dont think this is the best way to shutdown.  Should start by trying
  // to close all the sessions.
  m_io_loop->stop();
  m_evl->stop();

  m_evl.reset();
}


void client_service::start()
{
  /* USER thread */

  m_io_loop->start(); // returns immediately
}

Logger * client_service::get_logger()
{
  return __logptr;
}

IOLoop*  client_service::get_io()
{
  return m_io_loop.get();
}

event_loop* client_service::get_event_loop()
{
  return m_evl.get();
}


//----------------------------------------------------------------------

// void client_service::add_topic(topic* topic)
// {
//   // TODO: check that it is uniqyue
//   std::unique_lock<std::mutex> guard(m_topics_lock);
//   m_topics[ topic->uri() ] = topic;

//   // observer the topic for changes, so that changes can be converted into to
//   // publish messages sent to peer
//   topic->add_observer(
//     this,
//     [this](const XXX::topic* src,
//            const jalson::json_value& patch)
//     {
//       /* USER thread */

//       size_t router_session_count = 0;
//       {
//         std::unique_lock<std::mutex> guard(m_router_sessions_lock);
//         router_session_count = m_router_sessions.size();
//       }

//       if (router_session_count>0)
//       {
//         // TODO: legacy approach of publication, using the EV thread. Review
// 		    // this once topic implementation has been reviewed.
//         auto sp = std::make_shared<ev_outbound_publish>(src->uri(),
//                                                         patch,
//                                                         router_session_count);
//         {
//           std::unique_lock<std::mutex> guard(m_router_sessions_lock);
//           for (auto & item : m_router_sessions)
//           {
//             session_handle sh = item.second->handle();
//             sp->targets.push_back( sh );
//           }
//         }
//         m_evl->push( sp );
//       }


//       // TODO: here, I need to obtain our session to the router, so that topic
//       // updates can be sent to the router, for it to the republish as events.
//       // Currently we have not stored that anywhere.

//       // generate an internal event destined for the embedded
//       // router
//       // if (m_embed_router != nullptr)
//       // {
//       //   ev_internal_publish* ev = new ev_internal_publish(src->uri(),
//       //                                                   patch);
//       //   ev->realm = m_config.realm;
//       //   m_evl->push( ev );
//       // }
//     });
// }


// void client_service::handle_event(ev_router_session_connect_fail* ev)
// {
//   /* EV thread */
//   const t_connection_id router_session_id = ev->user_conn_id;

//   std::unique_lock<std::mutex> guard(m_router_sessions_lock);

//   auto iter = m_router_sessions.find( router_session_id );
//   if (iter != m_router_sessions.end())
//   {
//     router_conn * rs = iter->second;
//     if (rs->m_user_cb)
//       try {
//         rs->m_user_cb(rs, ev->status, false);
//       }
//       catch (...){}
//   }
// }


router_conn::router_conn(client_service * __svc,
                         std::string realm,
                         router_session_connect_cb __cb,
                         void * __user)
  : user(__user),
    m_svc(__svc),
    __logptr(__svc->get_logger() ),
    m_realm(std::move(realm)),
    m_user_cb(__cb)
{
}

int router_conn::connect(const std::string & addr, int port)
{
  tcp_connect_cb cb = [this](IOHandle* iohandle, int err){
    /* IO thread */

    _INFO_("router_conn::connect, err:" << err);
    if (iohandle)
    {

      session_state_fn fn = [this](session_handle, bool is_open){
        if (m_user_cb) m_user_cb(this, 0, is_open);
      };


      int sid= 0;
      m_session = std::shared_ptr<Session>
        (new Session( SID(sid),
                      m_svc->get_logger(),
                      iohandle,
                      *m_svc->get_event_loop(),
                      false,
                      m_realm, std::move(fn)));
      m_session->initiate_handshake();
    }
    else
    {
      if (m_user_cb)
      {
        // notify user on event-thread
        m_svc->get_event_loop()->push([this,err](){
            m_user_cb(this, err, false);
          });
      }
    }
  };

  m_svc->get_io()->add_connection(addr, port, cb);
  return 0;
}


t_request_id router_conn::call(std::string uri,
                               const jalson::json_object& options,
                               wamp_args args,
                               wamp_call_result_cb user_cb,
                               void* user_data)
{
  if (m_session)
    return m_session->call(uri, options, args, user_cb, user_data);
  else
    return 0;
}

t_request_id router_conn::subscribe(const std::string& uri,
                                    const jalson::json_object& options,
                                    subscription_cb user_cb,
                                    void * user_data)
{
  if (m_session)
    return m_session->subscribe(uri, options, user_cb, user_data);
  else
    return 0;
}


t_request_id router_conn::publish(const std::string& uri,
                                  const jalson::json_object& options,
                                  wamp_args args)
{
  if (m_session)
    return m_session->publish(uri, options, args);
  else
    return 0;
}



t_request_id router_conn::provide(const std::string& uri,
                                  const jalson::json_object& options,
                                  rpc_cb user_cb,
                                  void * user_data)
{
  if (m_session)
    return m_session->provide(uri, options, user_cb, user_data);
  else
    return 0;
}


} // namespace XXX
