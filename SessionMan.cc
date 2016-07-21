
#include "SessionMan.h"

#include "event_loop.h"
#include "kernel.h"
#include "wamp_session.h"

#include "WampTypes.h"


#include <string.h>

#define MAX_PENDING_OPEN_SECS 5

namespace XXX
{

SessionMan::SessionMan(kernel& k)
  : __logger(k.get_logger())
{
}

void SessionMan::session_closed(session_handle sh)
{
  auto sp = sh.lock();
  if (!sp) return;

  {
    std::lock_guard<std::mutex> guard(m_sessions.lock);

    t_sid sid ( sp->unique_id() );

    auto it = m_sessions.active.find( sid );

    if (it != m_sessions.active.end())
    {
      m_sessions.active.erase( it );
    }
  }
}

//----------------------------------------------------------------------

// void SessionMan::handle_housekeeping_event()
// {

//   // scan for sessions that failed to complete the handshake, or which are not
//   // sending heartbeats
//   {
//     std::lock_guard<std::mutex> guard(m_sessions.lock);
//     for (auto i : m_sessions.active)
//     {

//       if (i.second->is_pending_open() &&
//           i.second->duration_since_creation() >= MAX_PENDING_OPEN_SECS)
//       {
//         // expire sessions which have spent too long in pending-open
//         _WARN_("timeout during handshake, closing session #" << i.second->unique_id());
//         i.second->close();
//       }
//       else if ( i.second->is_open() &&
//                 i.second->uses_heartbeats() &&
//                 (i.second->duration_since_last() > i.second->hb_interval_secs()*3))
//       {
//         // expire sessions which appear inactive
//         _WARN_("missing heartbeats, closing session #" << i.second->unique_id());
//         i.second->close();
//       }
//     }

//   }
// }


void SessionMan::add_session(std::shared_ptr<wamp_session> sp)
{
  /* IO thread */
  std::lock_guard<std::mutex> guard(m_sessions.lock);
  m_sessions.active[ sp->unique_id() ] = sp;
}


}
