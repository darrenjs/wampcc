/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/socket_address.h"

#include <uv.h>
#include <string.h>

namespace wampcc
{

socket_address::socket_address()
  : m_impl(new sockaddr_storage())
{
}


socket_address::socket_address(const socket_address& other)
  : m_impl(new sockaddr_storage(*(other.m_impl.get())))
{
}


socket_address::socket_address(socket_address&& other)
  : m_impl() // null pointer held, but only until swapped
{
  this->swap(other);
}


socket_address::socket_address(const sockaddr_storage& other)
  : m_impl(new sockaddr_storage(other))
{
}


socket_address::~socket_address() = default;


/* This assignment operator makes use of the copy constructor. */
socket_address& socket_address::operator=(socket_address other)
{
  this->swap(other);
  return *this;
}


void socket_address::swap(socket_address& other)
{
  m_impl.swap(other.m_impl);
}


bool socket_address::operator==(const socket_address& other) const
{
  if (m_impl.get() && other.m_impl.get())
    return (::memcmp(m_impl.get(), other.m_impl.get(), sizeof (sockaddr_storage)) == 0);
  else if ((m_impl.get() == nullptr) && (other.m_impl.get()==nullptr))
    return true;
  else
    return false;
}


bool socket_address::operator!=(const socket_address& other) const
{
  return !(*this == other);
}


bool socket_address::is_ipv4() const {
  sockaddr_storage* ss = m_impl.get();
  return (ss != nullptr) && (ss->ss_family == AF_INET);
}


bool socket_address::is_ipv6() const {
  sockaddr_storage* ss = m_impl.get();
  return (ss != nullptr) && (ss->ss_family == AF_INET6);
}


std::string socket_address::to_string() const
{
  sockaddr_storage* ss = m_impl.get();
  if (ss == nullptr)
    return {};

  char text[64] = {}; // must be bigger ten IPv6 address (45 chars)

  if (ss->ss_family == AF_INET)
    uv_ip4_name((const struct sockaddr_in*) ss, text, sizeof text);
  else if (ss->ss_family == AF_INET6)
    uv_ip6_name((const struct sockaddr_in6*) ss, text, sizeof text);

  text[(sizeof text) - 1] = '\0';

  return text;
}


} // namespace wampcc
