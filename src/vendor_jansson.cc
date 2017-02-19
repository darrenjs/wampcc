/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "jansson.h"

#include "wampcc/json.h"

#include <string>
#include <sstream>
#include <iostream>

#include <string.h>

/* outside of jalson namespace, so not to confuse jalson names with JANSSON names */
static wampcc::json_value decode_jansson_ptr3(json_t * j)
{
  switch( json_typeof(j) )
  {
    case JSON_OBJECT :
    {
      wampcc::json_value rv = wampcc::json_value::make_object();
      wampcc::json_object& obj = rv.as<wampcc::json_object>();

      const char *key;
      json_t *value;
      json_object_foreach(j, key, value)
      {
        // TODO: why cant I use insert here?

//        obj.insert(key, decode_jansson_ptr3(value));
        obj[key]=decode_jansson_ptr3(value);
      }
      return rv;
    }
    case JSON_ARRAY :
    {
      wampcc::json_value rv = wampcc::json_value::make_array();
      wampcc::json_array& arr = rv.as<wampcc::json_array>();

      size_t index;
      json_t *value;
      json_array_foreach(j, index, value)
      {
        arr.push_back( decode_jansson_ptr3(value) );
      }

      return rv;
    }
    case JSON_STRING :
    {
      return wampcc::json_value(json_string_value(j), json_string_length(j));
    }
    case JSON_INTEGER :
    {
      long long i = json_integer_value(j);
      return wampcc::json_value(i);
    }
    case JSON_REAL :
    {
      return wampcc::json_value( json_real_value(j) );
    }
    case JSON_TRUE : return wampcc::json_value(true);
    case JSON_FALSE : return wampcc::json_value(false);
    case JSON_NULL : return wampcc::json_value();
    default : return wampcc::json_value();
  }

}



static json_t * encode_value3(const wampcc::json_value& src)
{
  switch( src.type() )
  {
    case wampcc::eOBJECT:
    {
      const wampcc::json_object& obj = src.as_object();

      json_t* jobj = json_object();

      for (wampcc::json_object::const_iterator iter = obj.begin();
           iter != obj.end(); ++iter )
      {
        json_object_set_new(jobj,
                            iter->first.c_str(),
                            encode_value3(iter->second));
      }
      return jobj;
    }
    case wampcc::eARRAY :  {
      const wampcc::json_array& _array = src.as_array();

      json_t* jarray = json_array();

      for (wampcc::json_array::const_iterator iter = _array.begin();
           iter != _array.end(); ++iter)
      {
        // TODO: is this the correct function? there is another one, and the
        // only difference it memory management
        json_array_append_new(jarray, encode_value3( *iter ));
      }

      return jarray;
    }
    case wampcc::eSTRING:
    {
      const wampcc::json_string& actual = src.as_string();
      return json_stringn(actual.c_str(), actual.size());
    }
    case wampcc::eREAL:
    {
      return json_real( src.as_real() );
    }
    case wampcc::eINTEGER:
    {
      if (src.is_int())
      {
        return json_integer( src.as_int() );
      }
      else
      {
        // This is the best we can do ... force our uint64 into an signed int.
        // Size is same.  Just better hope caller is aware.
        return json_integer( (int64_t)src.as_uint() );
      }
    }
    case wampcc::eBOOL:
    {
      if (src.as_bool())
        return json_true();
      else
        return json_false();
    }
//    case wampcc::eTRUE:   { return json_true();  }
//    case wampcc::eFALSE:  { return json_false(); }
    case wampcc::eNULL:   { return json_null();  }
    default: return NULL;
  }
}


namespace wampcc {
 const char impl_name[] = "jansson";

void get_vendor_details(vendor_details* p)
{
  memset(p,0,sizeof(vendor_details));
  p->vendor = impl_name;
  p->major_version = JANSSON_MAJOR_VERSION;
  p->minor_version = JANSSON_MINOR_VERSION;
  p->micro_version = JANSSON_MICRO_VERSION;

  p->has_encode_any = true;

}

static bool jansson_malloc_set = false;

struct malloc_guard
{
  ~malloc_guard()
  {
    jansson_malloc_set = true;
  }
};

static void * json_malloc(size_t s)
{
  //printf("malloc: %i\n", s);
  return ::operator new(s);   // C++ style memory alloc
}

static void json_free(void * p)
{
  ::operator delete(p); // C++ style memory release
}


std::string json_encode(const json_value& src)
{
  malloc_guard setflag_at_exit;
  if (!jansson_malloc_set) json_set_alloc_funcs(&json_malloc, &json_free);

  json_t* json = encode_value3( src );

  char * str = json_dumps(json, 0);

  // clean up the json device (will call free)
  json_decref( json );
  json = 0;

  std::string retval( str );
  json_free( str );

  return retval;
}


std::string json_encode_any(const json_value& src)
{
  malloc_guard setflag_at_exit;
  if (!jansson_malloc_set) json_set_alloc_funcs(&json_malloc, &json_free);

  json_t* json = encode_value3( src );

  char * str = json_dumps(json, JSON_ENCODE_ANY);

  // clean up the json device (will call free)
  json_decref( json );
  json = 0;

  std::string retval( str );
  json_free( str );

  return retval;
}

// TODO: need to handle the error cases in here
void json_decode(json_value& dest, const char* buffer)
{
  malloc_guard setflag_at_exit;
  if (!jansson_malloc_set) json_set_alloc_funcs(&json_malloc, &json_free);

  json_error_t error;

  json_t* root = json_loads(buffer, 0, &error);

  if (root == NULL)
  {
    std::ostringstream os;
    os << "error=" << error.text << " "
       << "line=" << error.line << " "
       << "column=" << error.column << " "
       << "position=" << error.position;

    parse_error perr( os.str() );
    perr.error = error.text;
    perr.source = error.source;
    perr.line = error.line;
    perr.position = error.position;
    perr.column = error.column;
    throw perr;
  }
  else
  {
    // TODO: this is not efficient; would be better to pass 'dest' into the
    // decode function.
    dest = decode_jansson_ptr3(root);
  }

  // clean up the json device
  if (root) json_decref( root );
}



json_value json_decode(const char* buffer)
{
  json_value dest;
  json_decode(dest, buffer);
  return dest;
}

// TODO: need to handle the error cases in here
void decode(json_value& dest, const char* buffer, size_t buflen)
{
  malloc_guard setflag_at_exit;
  if (!jansson_malloc_set) json_set_alloc_funcs(&json_malloc, &json_free);

  json_error_t error;

  json_t* root = json_loadb(buffer, buflen, 0, &error);

  if (root == NULL)
  {
    std::ostringstream os;
    os << "error=" << error.text << " "
       << "line=" << error.line << " "
       << "column=" << error.column << " "
       << "position=" << error.position;

    parse_error perr( os.str() );
    perr.error = error.text;
    perr.source = error.source;
    perr.line = error.line;
    perr.position = error.position;
    perr.column = error.column;
    throw perr;
  }
  else
  {
    // TODO: this is not efficient; would be better to pass 'dest' into the
    // decode function.
    dest = decode_jansson_ptr3(root);
  }

  // clean up the json device
  if (root) json_decref( root );
}

json_value json_decode(const char* buffer, size_t buflen)
{
  json_value dest;
  decode(dest, buffer, buflen);
  return dest;
}


}






//----------------------------------------------------------------------
