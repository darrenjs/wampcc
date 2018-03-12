/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/ssl.h"
#include "wampcc/log_macros.h"

namespace wampcc
{

sslstatus get_sslstatus(SSL* ssl, int n)
{
  switch (SSL_get_error(ssl, n))
  {
    case SSL_ERROR_NONE:
      return sslstatus::ok;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return sslstatus::want_io;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      return sslstatus::fail;
  }
}

ssl_context::ssl_context(logger & l,
                         const ssl_config& conf)
  : __logger(l),
    m_ctx(nullptr),
    m_config(conf)
{
  /* SSL library initialisation */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  if (conf.custom_ctx_creator == nullptr)
  {
    // create default SSL context
    m_ctx = SSL_CTX_new(SSLv23_method());
    if (!m_ctx)
      throw_ssl_error("SSL_CTX_new failed");

    if (!m_config.certificate_file.empty() &&
        !m_config.private_key_file.empty())
    {
      /* Load certificate and private key files, and check consistency  */
      if (SSL_CTX_use_certificate_file(m_ctx, m_config.certificate_file.c_str(),
                                       SSL_FILETYPE_PEM) != 1)
        throw_ssl_error("SSL_CTX_use_certificate_file");

      /* Indicate the key file to be used */
      if (SSL_CTX_use_PrivateKey_file(m_ctx, m_config.private_key_file.c_str(),
                                      SSL_FILETYPE_PEM) != 1)
        throw_ssl_error("SSL_CTX_use_PrivateKey_file");

      /* Make sure the key and certificate file match */
      if (SSL_CTX_check_private_key(m_ctx) != 1)
        throw_ssl_error("SSL_CTX_check_private_key");
    }

    /* Recommended to avoid SSLv2 & SSLv3 */
    SSL_CTX_set_options(m_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

#ifdef SSL_CTX_set_ecdh_auto
    /* Enable automatic ECDH selection */
    if (SSL_CTX_set_ecdh_auto(m_ctx, 1) != 1)
      throw_ssl_error("SSL_CTX_set_ecdh_auto");
#endif
  }
  else
  {
    // use customised context
    m_ctx = (conf.custom_ctx_creator)(conf);
    if (m_ctx == nullptr)
      throw_ssl_error("Failed to create custom ssl context");
  }
}


void ssl_context::log_ssl_error_queue()
{
  unsigned long l;
  char buf[256];

  while ((l = ERR_get_error()) != 0) {
    ERR_error_string_n(l, buf, sizeof buf);
    LOG_ERROR("ssl " << buf);
  }
}


ssl_session::ssl_session(ssl_context* ctx, connect_mode cm)
  : ssl(nullptr),
    rbio(nullptr),
    wbio(nullptr)
{
  if (ctx == nullptr)
    throw std::runtime_error("wampcc kernel SSL context is null");

  rbio = BIO_new(BIO_s_mem());
  wbio = BIO_new(BIO_s_mem());
  ssl = SSL_new(ctx->context());
  SSL_set_bio(ssl, rbio, wbio);

  if (cm == connect_mode::active)
    SSL_set_connect_state(ssl);
  if (cm == connect_mode::passive)
    SSL_set_accept_state(ssl);
}


ssl_session::~ssl_session()
{
  if (ssl)
    SSL_free(ssl); // will also free associated BIO
}


std::string to_string(sslstatus s)
{
  switch (s)
  {
    case sslstatus::ok : return "ok";
    case sslstatus::want_io : return "want_io";
    case sslstatus::fail : return "fail";
  }

  return "unknown_enum";
}


} // namespace
