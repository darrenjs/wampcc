#ifndef XXX_ERROR_H
#define XXX_ERROR_H

#include <system_error>

namespace XXX {


/** */
class uverr
{
private:
  int m_value;

public:
  uverr() noexcept : m_value(0) {}
  uverr(int v) noexcept : m_value(v) {}

  int value() const noexcept { return m_value; }

  int os_value() const noexcept {
#ifdef _WIN32
    return m_value;
#else
    return - m_value;
#endif
  }

  /** Assign a new error value */
  uverr& operator=(int v) noexcept { m_value = v; return *this; }

  /** Check if error value is non-zero, indicating an error */
  explicit operator bool() const noexcept { return m_value != 0; }

  /* Obtain explanatory error message related to error value */
  std::string message() const;
};


inline bool operator==(uverr  __lhs, uverr __rhs) noexcept
{ return __lhs.value() == __rhs.value();}

inline bool operator!=(uverr  __lhs, uverr __rhs) noexcept
{ return __lhs.value() != __rhs.value();}


template<typename _CharT, typename _Traits> std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& __os, uverr __e)
{
#ifdef _WIN32
  // on windows, indicate libuv error
  if (__e.value() != 0)
    return (__os << "uverr: " << __e.os_value() << ", " << __e.message());
  else
    return (__os << "uverr: 0");
#else
  // on linux, display the Unix error codes
  if (__e.value() != 0)
    return (__os << __e.os_value() << ", " << __e.message());
  else
    return (__os << "0");

#endif



}

}



#endif
