#include "Callbacks.h"



namespace XXX {




std::ostream& operator<<(std::ostream& os, const SID & s)
{
  os << s.m_unqiue_id;
  return os;
}



}
