/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/utils.h"
#include "wampcc/log_macros.h"
#include "wampcc/platform.h"

#include <openssl/hmac.h> // crypto functions
#include <string.h>

#include <assert.h>

#ifndef _WIN32
#include <regex.h>
#endif

namespace wampcc {


/*
  Compute the HMAC-SHA256 using a secret over a message.

  On success, zero is returned.  On error, -1 is returned.
 */
int compute_HMACSHA256(const char* key,
                       int keylen,
                       const char* msg,
                       int msglen,
                       char * dest,
                       unsigned int * destlen,
                       HMACSHA256_Mode output_mode)
{
  const char * hexalphabet="0123456789abcdef";
  const char * base64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  int retval = -1;  /* success=0, fail=-1 */

  /* initialise HMAC context */
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);

  unsigned char md[EVP_MAX_MD_SIZE + 1]; // EVP_MAX_MD_SIZE=64
  memset(md, 0, sizeof(md));
  unsigned int mdlen;

  HMAC(EVP_sha256(),
       key, keylen,
       (const unsigned char*) msg, msglen,
       md, &mdlen);

  if (output_mode == HMACSHA256_Mode::HEX)
  {
    // convert to hex representation in the output buffer
    if ( (mdlen*2) > *destlen)
    {
      // cannot encode
    }
    else
    {
      unsigned int i,j;
      for (i=0, j=0; i<mdlen; ++i,j+=2)
      {
        dest[j]   = hexalphabet[( md[i] >>4) & 0xF];
        dest[j+1] = hexalphabet[  md[i] & 0xF];
      }
      if (*destlen > (mdlen*2)+1)
      {
        dest[ mdlen*2 ] ='\0';
        *destlen = mdlen*2 + 1;
      }
      else
      {
        *destlen = mdlen*2;
      }
      retval = 0;
    }
  }
  else if (output_mode == HMACSHA256_Mode::BASE64)
  {
    /* Base 64 */
    unsigned int i = 0;
    int j = 0;
    const int jmax = * destlen;

    while ( i < mdlen)
    {
      char t[3];  // we encode three bytes at a time
      t[0]=0;
      t[1]=0;
      t[2]=0;

      unsigned int b = 0;
      for(b=0; b<3 && i<mdlen;)
      {
        if (i<mdlen) t[b] = md[i];
        b++;
        i++;
      }

      // b is now count of input bytes
      int idx[4];
      idx[0] = (t[0]&0xFC)>> 2;
      idx[1] = ((t[0]&0x3)<<4) | (t[1]>>4 & 0xF);
      idx[2] = ((t[1]&0xF)<<2) | ((t[2]&0xC0) >> 6 );
      idx[3] = (t[2] & 0x3F);

      switch (b)
      {
        case 1 :
        {
          if (j < jmax) { dest[j] = base64[ idx[0] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = base64[ idx[1] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = '='; j++; }
          if (j < jmax) { dest[j] = '='; j++; }
          break;
        }
        case 2 :
        {
          if (j < jmax) { dest[j] = base64[ idx[0] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = base64[ idx[1] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = base64[ idx[2] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = '='; j++; }
          break;
        }
        case 3 :
        {
          if (j < jmax) { dest[j] = base64[ idx[0] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = base64[ idx[1] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = base64[ idx[2] & 0x3F ]; j++; }
          if (j < jmax) { dest[j] = base64[ idx[3] & 0x3F ]; j++; }
          break;
        }
      }
    }
    if (j < jmax) { dest[j] = '\0';  retval = 0; *destlen=j+1;}
  }

  /* cleanup HMAC */
  HMAC_CTX_cleanup(&ctx);

  return retval;
}

void log_exception(logger & __logger, const char* callsite)
{
  try {
    throw;
  }
  catch (std::exception& e)
  {
    LOG_WARN("exception thrown for " << callsite << " : " << e.what());
  }
  catch (...)
  {
    LOG_WARN("exception thrown for " << callsite << " : unknown");
  }
}


std::string iso8601_utc_timestamp()
{
  static constexpr char full_format[]  = "2017-05-21T07:51:17.000Z"; // 24
  static constexpr char short_format[] = "2017-05-21T07:51:17";      // 19
  static constexpr int  short_len = 19;

  static_assert(short_len == (sizeof short_format - 1), "short_len check failed");

  wampcc::time_val tv = wampcc::time_now();

  char buf[32] = { 0 };
  assert(sizeof buf > (sizeof full_format));
  assert(sizeof full_format > sizeof short_format);

  struct tm timeinfo;
  time_t rawtime = tv.sec;

#ifndef _WIN32
  gmtime_r(&rawtime, &timeinfo);
#else
  gmtime_s(&timeinfo, &rawtime);
#endif

  if (0 == strftime(buf, sizeof buf - 1, "%FT%T", &timeinfo))
    return "";  // strftime not successful

  // append milliseconds
  int ec;
#ifndef _WIN32
  ec = snprintf(&buf[short_len], sizeof(buf) - short_len,
                ".%03dZ", (int) tv.usec/1000);
#else
  ec = sprintf_s(&buf[short_len], sizeof(buf) - short_len,
                 ".%03dZ", (int) tv.usec/1000);
#endif
  if (ec<0)
    return "";

  buf[sizeof full_format - 1] = '\0';
  return buf;
}


std::string random_ascii_string(const size_t len,
                                unsigned int seed)
{
  std::string temp;
  temp.reserve(len);

  std::mt19937 engine(seed);
  std::uniform_int_distribution<> distr('!', '~'); // asci printables

  for (auto & x : temp)
    x = distr(engine);

  temp[len] = '\0';
  return temp;
}


std::string to_hex(const char * p,
                   size_t size)
{
  static const char digits[] = "0123456789abcdef";
  std::string s(size*2,' ');

  for (size_t i = 0; i < size; ++i)
  {
    unsigned char uc = p[i];
    s[i * 2 + 0] = digits[(uc & 0xF0) >> 4];
    s[i * 2 + 1] = digits[(uc & 0x0F)];
  }

  return s;
}


std::list<std::string> tokenize(const char* src,
                                char delim,
                                bool want_empty_tokens)
{
  std::list<std::string> tokens;

  if (src && *src != '\0')
    while( true )  {
      const char* d = strchr(src, delim);
      size_t len = (d)? d-src : strlen(src);

      if (len || want_empty_tokens)
        tokens.push_back( { src, len } ); // capture token

      if (d) src += len+1; else break;
    }
  return tokens;
}


bool case_insensitive_same(const std::string &lhs,
                           const std::string &rhs)
{
  /* TODO: remove this check, should not be needed */
  return strcasecmp(lhs.c_str(), rhs.c_str()) == 0;
}

bool is_valid_char(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
    (c >= '0' && c <= '9') || (c == '_');
}

/* Check URI conformance directly, rather than use regex.  This is to avoid
 * compilers with broken regex implementations (eg, some gcc 4.x). */
bool is_strict_uri(const char* p) noexcept
{
  enum class state {component,component_or_delim,fail} st = state::component;

  while (st != state::fail && *p) {
    switch (st) {
      case state::component: {
        if (is_valid_char(*p))
          st = state::component_or_delim;
        else
          st = state::fail;
        break;
      }
      case state::component_or_delim: {
        if (*p == '.')
          st = state::component;
        else if (!is_valid_char(*p))
          st = state::fail;
        break;
      }
      case state::fail:
        break;
    };
    p++;
  }

  return st == state::component_or_delim;
}


} // namespace wampcc
