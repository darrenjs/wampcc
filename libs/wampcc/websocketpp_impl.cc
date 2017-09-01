/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/websocketpp_impl.h"

namespace wampcc
{

std::string websocketpp_impl::frame_to_string(
    const websocket_config::message_type::ptr& ptr)
{
  std::ostringstream oss;
  oss <<"fin " << ptr->get_fin() <<
    ", opcode " << ptr->get_opcode() <<
    ", payload_len " << ptr->get_payload().size();
  return oss.str();
}

}
