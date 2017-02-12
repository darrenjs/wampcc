#include <wampcc/error.h>

#include <uv.h>

namespace wampcc {

std::string uverr::message() const
{
  const char * s = uv_strerror(m_value); /* Can leak memory */
  return s? s : "unknown";
}

}
