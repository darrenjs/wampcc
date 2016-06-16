#ifndef XXX_WAMP_UTILS_H
#define XXX_WAMP_UTILS_H

#include <stdint.h>

namespace XXX {

class global_scope_id_generator
{
public:
  static const uint64_t m_min = 0;
  static const uint64_t m_max = 9007199254740992ull;

  global_scope_id_generator()
    : m_next(0)
  {
  }

  uint64_t next()
  {
    if (m_next > m_max)
      m_next = 0;

    return m_next++;
  }

private:
  uint64_t m_next;
};

}

#endif
