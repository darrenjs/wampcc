/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_ERROR_H
#define WAMPCC_ERROR_H

#include <string>

namespace wampcc {

/** Stores a libuv system error code, as returned from underlying libuv system
 * call wrappers. */
class uverr
{
private:
  int m_value;

public:
  /** Default constructor represents no-error situation. */
  uverr() noexcept : m_value(0) {}

  uverr(int libuv_error_code) noexcept : m_value(libuv_error_code) {}

  /** Return libuv error code */
  int value() const noexcept { return m_value; }

  /** Attempt to convert the libuv error value into a OS specific value. Only
   * suitable for unix platforms. */
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


inline bool operator==(uverr lhs, uverr rhs) noexcept
{ return lhs.value() == rhs.value();}


inline bool operator!=(uverr lhs, uverr rhs) noexcept
{ return lhs.value() != rhs.value();}

template<typename _CharT, typename _Traits> std::basic_ostream<_CharT, _Traits>&
operator<<(std::basic_ostream<_CharT, _Traits>& os, uverr ec)
{
#ifdef _WIN32
  // on windows, indicate libuv error
  if (ec.value() != 0)
    return (os << "uverr: " << ec.os_value() << ", " << ec.message());
  else
    return (os << "uverr: 0");
#else
  // on linux, display the Unix error codes
  if (ec.value() != 0)
    return (os << ec.os_value() << ", " << ec.message());
  else
    return (os << "0");
#endif
}

} // namespace

#endif
