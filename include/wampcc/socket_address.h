/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_SOCKET_ADDRESS_H
#define WAMPCC_SOCKET_ADDRESS_H

#include <string>
#include <memory>

// from sockets API
struct sockaddr_storage;

namespace wampcc
{

class tcp_socket;

/** Socket address, essentially a wrapper around the socket API's
 * sockaddr_storage structure, with some utility methods provided. */
class socket_address
{
public:
  socket_address();
  socket_address(const socket_address&);
  socket_address(socket_address&&);

  socket_address(const sockaddr_storage&);

  ~socket_address();

  socket_address& operator=(socket_address);

  bool operator==(const socket_address&) const;
  bool operator!=(const socket_address&) const;

  /** Is this address associated with an IPv4 socket? */
  bool is_ipv4() const;

  /** Is this address associated with an IPv6 socket? */
  bool is_ipv6() const;

  /** String representation of the address. */
  std::string to_string() const;

  void swap(socket_address&);

private:
  using impl_type = std::unique_ptr<sockaddr_storage>;
  impl_type m_impl;
  friend class tcp_socket;
};

} // namespace wampcc

#endif
