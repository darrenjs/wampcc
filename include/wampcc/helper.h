/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_HELPER_H
#define WAMPCC_HELPER_H

/*

This file contains various public utilites helpful to WAMP applications.

*/

#include <string>

namespace wampcc
{

struct uri_parts {
  std::string protocol;
  std::string domain;
  std::string port;
  std::string path;
  std::string query;
  std::string fragment;

  /** Parse the supplied URI string into its separate parts.  If the URI is
   * invalid, throws runtime_error. */
  static uri_parts parse(const std::string&);
};

} // namespace wampcc

#endif
