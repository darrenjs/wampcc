#include "event.h"

#include "Session.h"

namespace XXX {


ev_inbound_message::~ev_inbound_message()
{
  delete cb_data;
}

} // namespace xxx
