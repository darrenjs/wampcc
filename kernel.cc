#include "kernel.h"

#include "Logger.h"
#include "IOLoop.h"
#include "event_loop.h"

namespace XXX {

/* Constructor */
kernel::kernel(Logger* logptr)
  : __logptr(logptr),
    m_io_loop( new IOLoop(*this) ),
    m_evl( new event_loop(logptr) )
{
}

/* Destructor */
kernel::~kernel()
{
  // TODO: dont think this is the best way to shutdown.  Should start by trying
  // to close all the sessions.
  m_io_loop->stop();
  m_evl->stop();

  m_evl.reset();
}

void kernel::start()
{
  /* USER thread */

  m_io_loop->start(); // returns immediately
}

Logger * kernel::get_logger()
{
  return __logptr;
}

IOLoop*  kernel::get_io()
{
  return m_io_loop.get();
}

event_loop* kernel::get_event_loop()
{
  return m_evl.get();
}


} // namespace XXX
