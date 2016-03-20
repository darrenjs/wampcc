/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <jalson/jalson.h>

#include <string.h>
#include <stdlib.h>


/*

This file contains an implementation of:

    JavaScript Object Notation (JSON) Pointer

as defined in IETF RFC 6901.

 */



#define JPDELIM '/'

namespace jalson {

static json_value select_child(json_object& refvalue, const char* path2, size_t pathindex);
static json_value select_child(json_array& refvalue, const char* path2, size_t pathindex);




static size_t json_pointer_str_to_index(const char* s)
{
  // TODO: need better checking here
  return atoi(s);
}




static const char* has_escape_seq(const char* p, const char* end)
{
  while (p < end)
  {
    p = strchr(p, '~');
    if (!p) return 0;

    if ( ( p+1 < end) && (*(p+1) =='0' || *(p+1)=='1') ) return p;

    p++;
  }
  return 0;
}

static const char* has_escape_seq(const char* p)
{
  return has_escape_seq(p, p+strlen(p));
}

char* expand_str(const char* start, const char *end)
{
  // allocate memory
  char * cp = new char[end-start+1];
  char* dest = cp;
  const char* p = start;

  while (p < end)
  {
    if ( (*p == '~') && (p+1 < end) && (*(p+1)=='0' || *(p+1)=='1') )
    {
      *dest = (*(p+1) == '0')? '~' : '/';
      p++;
    }
    else
    {
      *dest = *p;
    }
    dest++;
    p++;
  }

  *dest = '\0';

  return cp;
}


json_value select_child(json_object& refvalue, const char* path, size_t pathindex)
{
  const char* next_delim = strchr(path, JPDELIM);

  std::string token = next_delim? std::string(path, next_delim-path) : path;
  const char * escaped = has_escape_seq(path, (next_delim)? next_delim : path+strlen(path));
  if (escaped)
  {
    char *  copy = expand_str( path, (next_delim)? next_delim : path+strlen(path));
    token = copy;
    delete [] copy;
  }

  json_object::iterator it = refvalue.find( token );
  if (it != refvalue.end())
  {

    if (next_delim)
    {
      if (it->second.is_array())
        return select_child(it->second.as_array(), next_delim+1, pathindex+1);
      else if (it->second.is_object())
        return select_child(it->second.as_object(), next_delim+1, pathindex+1);
      else
      {
        throw pointer_fail("value selected in object is not a container", pathindex);
      }
    }
    else
    {
      return it->second;
    }
  }
  else
  {
    throw pointer_fail("name not present in object", pathindex);
  }
}


static json_value select_child(json_array& refvalue, const char* path, size_t pathindex)
{
  const char* next_delim = strchr(path, JPDELIM);

  std::string token = next_delim? std::string(path, next_delim-path) : path;
  size_t index = json_pointer_str_to_index(token.c_str());

  if (index < refvalue.size() )
  {

    if (next_delim)
    {
      if (refvalue[index].is_array())
        return select_child(refvalue[index].as_array(), next_delim+1, pathindex+1);
      else if (refvalue[index].is_object())
        return select_child(refvalue[index].as_object(), next_delim+1, pathindex+1);
      else
      {
        throw pointer_fail("value selected in array is not a container", pathindex);
      }
    }
    else
    {
      return refvalue[index];
    }
  }
  else
  {
    throw pointer_fail("index not present in array", pathindex);
  }
}




json_value select(json_value& root, const std::string& path)
{
  const char* path2 = path.c_str();

  switch (*path2)
  {
    case '\0' :
    {
      // empty string , which implies the full document
      return root;
    }
    case JPDELIM :
    {
      if (root.is_array())
      {
        return select_child(root.as_array(),  path2+1 , 0);
      }
      else if (root.is_object())
      {
        return select_child(root.as_object(), path2+1, 0);
      }
      else
      {
        throw pointer_fail("root item not a container", 0);
      }
      break;
    }
    default :
    {
      throw pointer_fail("string is not a invalid pointer", 0);
    }
  }

}


}
