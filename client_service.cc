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
#include "Topic.h"

#include <iostream>

#include <unistd.h>
#include <string.h>


namespace XXX {



struct Request_Register_CD_Data : public Request_CB_Data
{
  std::string procedure;
};



//----------------------------------------------------------------------


/* Constructor */
client_service::client_service(Logger * logptr,
                               config config)
  : __logptr( logptr),
    m_config( config ),
    m_io_loop( new IOLoop(logptr) ),
    m_evl( new event_loop(logptr) ),
    m_sesman(new SessionMan(__logptr, *m_evl.get())),
    m_next_client_request_id(100)
{

  if (m_config.realm.empty()) throw std::runtime_error("config.realm cannot be empty");

  // TODO: make this a member
  client_event_handler local_handler;

  local_handler.handle_router_session_connect_fail=
    [this](ev_router_session_connect_fail* ev) { handle_event(ev); };


  m_evl->set_handler( local_handler );
  m_evl->set_session_man( m_sesman.get() );

  // TODO: remove this, and instead all the client_service directly from the event_loop
  m_sesman->set_session_event_listener(
    [this](ev_session_state_event* ev){this->handle_session_state_change(ev);});


  /* TODO: remove legacy interaction between IO thread and user space */
  m_io_loop->m_new_client_cb = [this](IOHandle* h, int status, int rid ){this->new_client(h, status, rid);};

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

//----------------------------------------------------------------------

void client_service::handle_session_state_change(ev_session_state_event* ev)
{
  /* EV thread */

  session_handle sh = ev->src;

  if (! ev->is_open)
  {


    // raise user callback to indicate session termination
    {
      std::unique_lock< std::mutex > guard(m_router_sessions_lock);
      auto iter = m_router_sessions.find( ev->user_conn_id );
      if (iter != m_router_sessions.end())
      {
        router_conn* rs = iter->second;
        if (rs->m_connection_cb)
          try {
            rs->m_connection_cb(rs, -ev->err, false); // TODO: core dump seen here
          } catch(...){}
      }
    }
    return;
  }

  _INFO_("session is now ready #" << ev->user_conn_id << " ... registering procedures");

  // publish our topics
  {
    std::lock_guard< std::mutex > guard ( m_topics_lock );
    for (auto & i : m_topics)
    {
      const std::string & uri = i.first;
//      topic* topic = i.second;

      build_message_cb_v2 msg_builder2 = [&uri](int request_id)
        {
          jalson::json_array msg;
          msg.push_back( PUBLISH );
          msg.push_back( request_id );
          msg.push_back( jalson::json_object() );
          msg.push_back( uri );
          msg.push_back( jalson::json_array() );

          // TODO: I now think this is a bad idea, ie, passing cb_data back via a lambda
          return std::pair< jalson::json_array, Request_CB_Data*> ( msg, nullptr );

        };

      // TODO: instead of 0, need to have a valie intenral request id
      m_sesman->send_request(sh, PUBLISH, 0, msg_builder2);
    }

  }

  // raise user callback to indicate session connection
  {
    std::unique_lock< std::mutex > guard(m_router_sessions_lock);
    auto iter = m_router_sessions.find( ev->user_conn_id );
    if (iter != m_router_sessions.end())
    {
      router_conn*  rs = iter->second;
      rs->m_internal_session_handle = sh;
      rs->m_session = m_sesman->get_session(sh);
      if (rs->m_connection_cb)
        try {
          rs->m_connection_cb(rs, 0, true);
        } catch(...){}
    }
  }


}

//----------------------------------------------------------------------

void client_service::new_client(IOHandle *h,
                                int  status,
                                t_connection_id user_conn_id)
{
  /* IO */

  // TODO: bad design here.  IO event should not come to here, and then into the session manager.
  if (h)
  {
    m_sesman -> create_session(h, false, user_conn_id, m_config.realm);
  }
  else
  {
    ev_router_session_connect_fail * ev = new ev_router_session_connect_fail(
      user_conn_id , status);
    m_evl->push( ev );
  }
}

//----------------------------------------------------------------------

void client_service::start()
{
  /* USER thread */

  m_io_loop->start(); // returns immediately
}


//----------------------------------------------------------------------

void client_service::add_topic(topic* topic)
{
  // TODO: check that it is uniqyue
  std::unique_lock<std::mutex> guard(m_topics_lock);
  m_topics[ topic->uri() ] = topic;

  // observer the topic for changes, so that changes can be converted into to
  // publish messages sent to peer
  topic->add_observer(
    this,
    [this](const XXX::topic* src,
           const jalson::json_value& patch)
    {
      /* USER thread */

      size_t router_session_count = 0;
      {
        std::unique_lock<std::mutex> guard(m_router_sessions_lock);
        router_session_count = m_router_sessions.size();
      }

      if (router_session_count>0)
      {
        // TODO: legacy approach of publication, using the EV thread. Review
		    // this once topic implementation has been reviewed.
        auto sp = std::make_shared<ev_outbound_publish>(src->uri(),
                                                        patch,
                                                        router_session_count);
        {
          std::unique_lock<std::mutex> guard(m_router_sessions_lock);
          for (auto & item : m_router_sessions)
          {
            session_handle sh = item.second->handle();
            sp->targets.push_back( sh );
          }
        }
        m_evl->push( sp );
      }


      // TODO: here, I need to obtain our session to the router, so that topic
      // updates can be sent to the router, for it to the republish as events.
      // Currently we have not stored that anywhere.

      // generate an internal event destined for the embedded
      // router
      // if (m_embed_router != nullptr)
      // {
      //   ev_internal_publish* ev = new ev_internal_publish(src->uri(),
      //                                                   patch);
      //   ev->realm = m_config.realm;
      //   m_evl->push( ev );
      // }
    });
}


int client_service::connect_session(router_conn& rs,
                                    const std::string & addr,
                                    int port)
{
  /* USER thread */

  m_io_loop->add_connection(addr,
                            port,
                            rs.router_session_id());
  return 0;
}



bool client_service::is_open(const router_conn* rs) const
{
  return m_sesman->session_is_open( rs->m_internal_session_handle );
}


void client_service::handle_event(ev_router_session_connect_fail* ev)
{
  /* EV thread */
  const t_connection_id router_session_id = ev->user_conn_id;

  std::unique_lock<std::mutex> guard(m_router_sessions_lock);

  auto iter = m_router_sessions.find( router_session_id );
  if (iter != m_router_sessions.end())
  {
    router_conn * rs = iter->second;
    if (rs->m_connection_cb)
      try {
        rs->m_connection_cb(rs, ev->status, false);
      }
      catch (...){}
  }
}

t_connection_id client_service::register_session(router_conn& rs)
{
  /* USER thread */

  std::unique_lock<std::mutex> guard(m_router_sessions_lock);
  t_connection_id id = m_next_router_session_id++;
  m_router_sessions[ id ] = &rs;

  return id;
}


router_conn::router_conn(client_service * __svc,
                         router_session_connect_cb __cb,
                         void * __user)
  : user(__user),
    m_svc(__svc),
    m_connection_cb(__cb),
    m_router_session_id( __svc->register_session( *this ) )
{
}

int router_conn::connect(const std::string & addr, int port)
{
  return m_svc->connect_session(*this, addr, port);
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


  Logger * client_service::get_logger() { return __logptr; }
  IOLoop* client_service::get_ioloop() { return m_io_loop.get(); }
  event_loop* client_service::get_event_loop() { return m_evl.get(); }
  SessionMan* client_service::get_session_man() { return m_sesman.get(); }


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
