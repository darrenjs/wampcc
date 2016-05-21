#ifndef __SESSIONMAN_H_
#define __SESSIONMAN_H_


#include "Callbacks.h"

#include "wamp_session.h"

#include <jalson/jalson.h>

#include <functional>
#include <map>
#include <mutex>
#include <vector>

namespace XXX {


  class kernel;
  class wamp_session;
  class Logger;

class SessionMan
{
public:

  SessionMan(kernel&);

  void add_session(std::shared_ptr<wamp_session>);
  void session_closed(session_handle sh);


  void handle_housekeeping_event( void );

private:

  // void heartbeat_all();

  kernel& m_kernel;
  Logger *__logptr; /* name chosen for log macros */

  mutable struct
  {
    std::mutex lock;
    std::map<t_sid, std::shared_ptr<wamp_session> > active;
    std::vector< std::shared_ptr<wamp_session> >  closed;
  } m_sessions;

};


} // namespace

#endif
