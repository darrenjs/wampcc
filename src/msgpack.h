/*
 * Copyright (c) 2017 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __JALSON_MSGPACK_H__
#define __JALSON_MSGPACK_H__

#include "wampcc/json.h"

#include "msgpack.hpp"

namespace wampcc
{

class msgpack_encoder
{
public:
  msgpack_encoder();
  std::pair<char *, size_t> encode(const json_array &);

private:
  msgpack::sbuffer m_sbuf;
  msgpack::packer<msgpack::sbuffer> m_packer;

  void pack_array(const json_array &);
  void pack_object(const json_object &);
  void pack_value(const json_value&);
  void pack_string(const std::string&);
};


class msgpack_decoder
{
public:
  json_value decode(const char *, size_t);
};




}

#endif
