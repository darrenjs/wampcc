#include "utils.h"
#include "log_macros.h"
#include <openssl/hmac.h> // crypto functions
#include <sys/time.h>

#include <string.h>
#include <regex.h>

namespace XXX {


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
  timeval epoch;
  gettimeofday(&epoch, nullptr);

  struct tm _tm;
  gmtime_r(&epoch.tv_sec, &_tm);

  // YYYY-MM-DDThh:mm:ss.sssZ
  char temp[32];
  memset(temp, 0, sizeof(temp));

  strftime(temp, sizeof(temp)-1, "%FT%T", &_tm);
  sprintf(&temp[19], ".%03dZ", (int) epoch.tv_usec/1000);
  temp[24]='\0';

  return temp;
}


std::string generate_random_string(const size_t len,
                                   unsigned int seed)
{
  char temp [len+1];

  std::mt19937 engine(seed);
  std::uniform_int_distribution<> distr('!', '~'); // asci printables

  for (auto & x : temp) x = distr(engine);
  temp[len] = '\0';

  return temp;
}


struct regex_impl
{
  regex_t m_re;

  regex_impl()
  {
    int flags = REG_EXTENDED|REG_NOSUB|REG_ICASE;
    if (::regcomp(&m_re, "^([0-9a-z_]+\\.)*([0-9a-z_]+)$", flags) != 0)
      throw std::runtime_error("regcomp failed");
  }

  ~regex_impl()
  {
    regfree(&m_re);
  }

  bool matches(const char * s) const
  {
    return (::regexec(&m_re, s, (size_t) 0, NULL, 0) == 0);
  }
};

uri_regex::uri_regex()
  : m_impl(new regex_impl)
{
}

uri_regex::~uri_regex()
{
  delete m_impl;
}


bool uri_regex::is_strict_uri(const char* s) const
{
  return m_impl->matches(s);
}

} // namespace XXX
