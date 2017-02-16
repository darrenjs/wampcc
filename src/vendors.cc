
// include the generated config file
#include "config.h"

#undef HAVE_SOME_VENDOR

#if defined(HAVE_JANSSON) && HAVE_JANSSON == 1
#include "vendor_jansson.cc"
#define HAVE_SOME_VENDOR 1
#endif


#ifndef HAVE_SOME_VENDOR
#error "No vendor implementation has been specified during software configuration stage. Please reconfigure the source."
#endif

