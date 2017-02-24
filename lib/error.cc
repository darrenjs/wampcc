/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <wampcc/error.h>

#include <uv.h>

namespace wampcc
{

const char* uverr::message() const
{
  const char* s = uv_strerror(m_value); /* Can leak memory */
  return s ? s : "unknown";
}
}
