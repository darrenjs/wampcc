
#include "SessionMan.h"

#include "event_loop.h"
#include "kernel.h"
#include "wamp_session.h"

#include "WampTypes.h"
#include "Logger.h"

#include <string.h>

#define MAX_PENDING_OPEN_SECS 3

namespace XXX
{

SessionMan::SessionMan(kernel& k)
  : m_kernel(k),
    __logptr(k.get_logger())
{
  m_kernel.get_event_loop()->set_session_man( this );
}


SessionMan::~SessionMan()
{
  std::lock_guard<std::mutex> guard(m_sessions.lock);
}


std::shared_ptr<wamp_session> SessionMan::create_session(IOHandle * iohandle, bool is_passive,
                                                    std::string realm)
{
  /* IO thread */

  std::lock_guard<std::mutex> guard(m_sessions.lock);

  // and chekc is not altready in the map.
  // Need to handle case where we wrap around
  // and have to skip zero ... actuall, to handle this, set start number to minus 1

  // TODO: its not the place here to configure the newly created session .
  // That should be done by the caller of this function.
  std::shared_ptr<wamp_session>  sptr (new wamp_session( __logptr,
                                               iohandle,
                                               *(m_kernel.get_event_loop()),
                                               is_passive,
                                               realm,
                                               nullptr));

  m_sessions.active[ sptr->unique_id() ] = sptr;

  _INFO_( "session created, id:" << sptr->unique_id() );
  if (!is_passive) sptr->initiate_handshake();

  return sptr;
}


void SessionMan::heartbeat_all()
{
  jalson::json_array msg;

  msg.push_back(HEARTBEAT);
  std::lock_guard<std::mutex> guard(m_sessions.lock);

  for (auto i : m_sessions.active)
  {
    if ( i.second->is_open() && i.second->hb_interval_secs())
    {
      // do heartbeat check on an open session
      if (i.second->duration_since_last() > i.second->hb_interval_secs()*3)
      {
        // expire sessions which appear inactive
          _WARN_("closing session due to inactivity " << i.second->hb_interval_secs() << ", " << i.second->duration_since_last());
          i.second->close();
      }
      else
      {
        i.second->send_msg(msg);
      }
    }

    if (i.second->is_pending_open())
    {
      if (i.second->duration_pending_open() >= MAX_PENDING_OPEN_SECS )
      {
        // expire sessions which have spent too long in pending-open
        _WARN_("closing session due to incomplete handshake");
        i.second->close();
      }
    }
  }
}


void SessionMan::close_all()
{
  std::lock_guard<std::mutex> guard(m_sessions.lock);

  for (auto i : m_sessions.active)
  {
    i.second->close();
  }
}


//----------------------------------------------------------------------

void SessionMan::send_to_session_impl(session_handle handle,
                                      jalson::json_array& msg)
{
  auto sp = handle.lock();
  if (!sp)
  {
    _WARN_("failed to lock the session handle");
    return;
  }

  t_sid dest( sp->unique_id() );
  if (dest == 0)
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
    _WARN_("session send failed; cannot find session with id " << dest);
  }
}


void SessionMan::send_to_session(const std::vector<session_handle>& handles,
                                 jalson::json_array& msg)
{
  std::lock_guard<std::mutex> guard(m_sessions.lock);

  for (auto & handle : handles)
  {
    try {
      send_to_session_impl(handle, msg);
    }
    catch (const std::exception& e)
    {
      _ERROR_("exception during msg send: " << e.what());
    }
  }
}


void SessionMan::handle_event(ev_session_state_event* ev)
{
  auto sp = ev->src.lock();
  if (!sp) return;

  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);

    t_sid sid ( sp->unique_id() );

    auto it = m_sessions.active.find( sid );

    if (it == m_sessions.active.end())
    {
      _ERROR_("ignoring session state event for non active session sid:" << sid);
      return;
    }


    if (ev->is_open == false)
    {
      m_sessions.active.erase( it );
      m_sessions.closed.push_back(sp);
    }
  }

  if (m_session_event_cb) m_session_event_cb(ev);
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

  std::vector< std::shared_ptr<wamp_session> > to_delete;

  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);
    to_delete.swap( m_sessions.closed );
  }

  to_delete.clear(); // expected to call ~wamp_session
}


}
