#include "event.h"

#include "Session.h"

namespace XXX {

event::~event()
{
  delete cb_data;
}

} // namespace xxx
