#include "utils.h"

#include <openssl/hmac.h> // crypto functions

#include <string.h>

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

void log_exception(Logger *__logptr, const char* callsite)
{
  try {
    throw;
  }
  catch (std::exception& e)
  {
    _WARN_("exception thrown for " << callsite << " : " << e.what());
  }
  catch (...)
  {
    _WARN_("exception thrown for " << callsite << " : unknown");
  }
}


} // namespace XXX
