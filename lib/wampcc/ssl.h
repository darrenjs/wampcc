/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef WAMPCC_SSL_H
#define WAMPCC_SSL_H

#include "wampcc/kernel.h"
#include "wampcc/types.h"

#include <iostream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

namespace wampcc
{

/* Represent the global context OpenSSL object. */
class ssl_context
{
public:
  ssl_context(const ssl_config& conf);

  /* log all entries in the SSL error queue */
  void log_ssl_error_queue();

  template <size_t N> void throw_ssl_error(const char (&what)[N])
  {
    char buf[N + 256];
    memset(buf, 0, sizeof buf);
    memcpy(buf, what, N);
    buf[N - 1] = ':'; // replace null char of `what` with colon

    // store the last error on the queue before logging all
    unsigned long lasterr = ERR_peek_last_error();

    log_ssl_error_queue();

    /* throw an exception using the last error */
    ERR_error_string_n(lasterr, buf + N, sizeof(buf) - N);
    buf[sizeof(buf) - 1] = '\0';
    throw std::runtime_error(buf);
  }

  SSL_CTX* context() { return m_ctx; };

private:
  SSL_CTX* m_ctx;
  ssl_config m_config;
};


/* Represent the objects & state associated with an SSL session. */
class ssl_session
{
public:
  SSL *ssl;

  BIO *rbio; /* SSL reads from, we write to. */
  BIO *wbio; /* SSL writes to, we read from. */

  /* Bytes waiting to be written to socket. This is data that has been generated
   * by the SSL object, either due to encryption of user input, or, writes
   * requires due to peer-requested SSL renegotiation. */
  char* write_buf;
  size_t write_len;

  /* Bytes waiting to be fed into the SSL object for encryption. */
  char* encrypt_buf;
  size_t encrypt_len;

  ssl_session(ssl_context* ctx, wampcc::connect_mode);
};


}

#endif
