
#include "SessionMan.h"

#include "event_loop.h"
#include "Session.h"

#include "WampTypes.h"
#include "Logger.h"
#include "session_state_listener.h"

#include <string.h>

namespace XXX
{

  SessionMan::SessionMan(Logger* logptr, event_loop& evl)
    : __logptr(logptr),
      m_evl(evl)
  {
    m_evl.set_session_man( this );
    m_sessions.m_next = 1;
  }


  SessionMan::~SessionMan()
  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);


    for (auto & item  : m_sessions.active)
      delete item.second;
    for (auto & item : m_sessions.closed)
      delete item;
  }


  Session* SessionMan::create_session(IOHandle * iohandle, bool is_dealer)
  {
    /* IO thread */

    std::lock_guard<std::mutex> guard(m_sessions.lock);
    SID sid (m_sessions.m_next++);  // TODO find a unqiue numner, dont use 0,
                                    // and chekc is not altready in the map.
                                    // Need to handle case where we wrap around
                                    // and have to skip zero ... actuall, to handle this, set start number to minus 1

    // TODO: its not the place here to configure the newly created session .
    // That should be done by the caller of this function.
    Session * sptr;
    sptr = new Session( sid,
                        __logptr,
                        iohandle,
                        this,
                        m_evl,
                        is_dealer);

    m_sessions.active[ sid ] = sptr;

    // Send the logon message
    //sptr->send("logon");


    _INFO_( "session created, id=" << sid );

    return sptr;
  }


  void SessionMan::heartbeat_all()
  {
    jalson::json_array msg;

    msg.push_back(HEARTBEAT);
    std::lock_guard<std::mutex> guard(m_sessions.lock);

    for (auto i : m_sessions.active)
    {
      i.second->send_msg(msg);
    }

  }


  void SessionMan::close_all()
  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);

    for (auto i : m_sessions.active)
    {
      // TODO: do I need to test if session is open?
      i.second->close(1);
    }
  }


  void SessionMan::session_closed(Session& s)
  {
    /* IO thread */

    std::lock_guard<std::mutex> guard(m_sessions.lock);

    // TODO tryong to do an immediate delete
    m_sessions.closed.push_back( & s );

    auto it = m_sessions.active.begin();
    while (it != m_sessions.active.end())
    {
      if (it->second == &s)
      {
        m_sessions.active.erase( it );
        it = m_sessions.active.begin();
      }
      else
        it++;
    }

    s.remove_listener();


    // TODO: here, could push an event
  }


// void SessionMan::on_timer()
// {

//   std::lock_guard<std::mutex> guard(m_sessions.lock);

//   for (auto & i : m_sessions.active)
//     i.second->on_timer();


//   // TODO: I can move the deletion to outside of the critical section.
//   _INFO_("deleting expired sessions: " << m_sessions.closed.size());
//   for (auto & i : m_sessions.closed) delete i;
//   m_sessions.closed.clear();
// }

//----------------------------------------------------------------------


void SessionMan::send_to_session(session_handle handle,
                                 build_message_cb_v4 msg_builder)
{
  std::lock_guard<std::mutex> guard(m_sessions.lock);

  auto sp = handle.lock();
  if (!sp)
  {
    _WARN_("failed to lock the session handle");
    return;
  }
  SID dest( *sp );


  if (dest == SID())
  {
    _WARN_("ignoring attempt to send to session with id 0");
    return;
  }

  auto it = m_sessions.active.find( dest );

  if (it != m_sessions.active.end())
  {
    it->second->send_msg( msg_builder );
  }
  else
  {
    std::ostringstream os;
    os << "session send failed; cannot find session with id " << dest.unique_id();
    throw std::runtime_error( os.str() );
  }
}

//----------------------------------------------------------------------

void SessionMan::send_to_session(session_handle handle, jalson::json_array& msg)
{
  std::lock_guard<std::mutex> guard(m_sessions.lock);

  auto sp = handle.lock();
  if (!sp)
  {
    _WARN_("failed to lock the session handle");
    return;
  }

  SID dest( *sp );
  if (dest == SID())
  {
    _WARN_("ignoring attempt to send to session with id 0");
    return;
  }

  bool is_final = false;

  auto it = m_sessions.active.find( dest );
  if (it != m_sessions.active.end())
  {
    it->second->send_msg(msg, is_final);
  }
  else
  {
    std::ostringstream os;
    os << "session send failed; cannot find session with id " << dest;
    throw std::runtime_error( os.str() );
  }
}

// void SessionMan::send_to_session(SID dest, jalson::json_array& msg)
// {
//   if (dest == SID())
//   {
//     _WARN_("ignoring attempt to send to session with id 0 : " << msg);
//     return;
//   }

//   bool is_final = false;
//   std::lock_guard<std::mutex> guard(m_sessions.lock);
//   auto it = m_sessions.active.find( dest );
//   if (it != m_sessions.active.end())
//   {
//     it->second->send_msg(msg, is_final);
//   }
//   else
//   {
//     std::ostringstream os;
//     os << "session send failed; cannot find session with id " << dest;
//     throw std::runtime_error( os.str() );
//   }
// }

//----------------------------------------------------------------------

void SessionMan::send_request(session_handle handle_weak,
                              int request_type,
                              unsigned int internal_req_id,
                              build_message_cb_v2 msg_builder)
{
  std::lock_guard<std::mutex> guard(m_sessions.lock);

  auto sp = handle_weak.lock();
  if (!sp)
  {
    _WARN_("failed to lock the session handle");
    return;
  }

  SID dest( *sp );
  if (dest == SID())
  {
    _WARN_("ignoring attempt to send to session with id 0");
    return;
  }


  auto it = m_sessions.active.find( dest );
  if (it != m_sessions.active.end())
  {
    it->second->send_request( request_type, internal_req_id, msg_builder );
  }
  else
  {
    throw std::runtime_error("cannot send to session; session not found");
  }
}

//----------------------------------------------------------------------

void SessionMan::handle_event(session_state_event* ev)
{
  Session* sptr = NULL;

  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);

    auto sp = ev->src.lock();
    if (!sp) return;
    SID sid ( *sp );


    auto it = m_sessions.active.find( sid );

    if (it == m_sessions.active.end())
    {
      _ERROR_("ignoring session state event for non active session sid:" << sid);
      return;
    }

    sptr = it->second;

    if (ev->is_open == false)
    {
      m_sessions.active.erase( it );
      m_sessions.closed.push_back(it->second);
    }
  }

  if (m_session_event_cb) m_session_event_cb(sptr, ev->is_open);
}

//----------------------------------------------------------------------

void SessionMan::set_session_event_listener(session_state_cb cb)
{
  m_session_event_cb = cb;
}

//----------------------------------------------------------------------

void SessionMan::handle_housekeeping_event()
{
  this->heartbeat_all();


  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);

    // TODO: I can move the deletion to outside of the critical section.
//    _INFO_("deleting expired sessions: " << m_sessions.closed.size());
    for (auto & i : m_sessions.closed) delete i;
    m_sessions.closed.clear();
  }
}

}
