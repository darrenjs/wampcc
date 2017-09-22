/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/helper.h"

#include <stdexcept>
#include <regex>

    //              PROTO         DOMAIN     PORT     PATH             QUERY     FRAGMENT
    //              12            3          4        5                6         7
#define URI_REGEX "^(([^:/?#]+):)?//([^/ :]+):?([^ /?#]*)(/?[^ #?]*)\\x3f?([^ #]*)#?([^ ]*)$"

namespace wampcc
{

uri_parts uri_parts::parse(const std::string& s)
{
  std::regex re(URI_REGEX);

  uri_parts rv;
  std::smatch m;

  if (std::regex_match(s, m, re))
  {
    rv.protocol = m[2];
    rv.domain = m[3];
    rv.port = m[4];
    rv.path = m[5];
    rv.query = m[6];
    rv.fragment = m[7];
  }
  else
    throw std::runtime_error("invalid URI");

  return rv;
}

} // namespace wampcc
