#include <XXX/error.h>

#include <uv.h>

namespace XXX {

std::string uverr::message() const
{
  const char * s = uv_strerror(m_value); /* Can leak memory */
  return s? s : "unknown";
}

}
