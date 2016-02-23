#ifndef XXX_UTILS_H
#define XXX_UTILS_H


// TODO: make an enum
#define HMACSHA256_HEX    0
#define HMACSHA256_BASE64 2

namespace XXX {

int compute_HMACSHA256(const char* key,
                       int keylen,
                       const char* msg,
                       int msglen,
                       char * dest,
                       unsigned int * destlen,
                       int output_mode);


} // namespace XXX

#endif
