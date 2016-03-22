/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <jalson/jalson.h>

#include <limits>

#include <string.h>
#include <stdlib.h>


/*

This file contains an implementation of:

    JavaScript Object Notation (JSON) Pointer (IETF RFC 6901)
    JavaScript Object Notation (JSON) Patch   (IETF RFC 6902)

 */



#define JPDELIM '/'

namespace jalson {

struct operation
{

  enum opcode
  {
    eAdd,
    eReplace,
    eRemove,
    eRead,
    eCut,     /* delete and keep a copy */
    eTest
  } action;


  const json_value * read_only;
//  json_value * target;
  json_value temp;

  operation(opcode op)
  : action(op),
    read_only(0)
  {
  }
};


static void  select_child(json_object& refvalue, const char* path2, size_t pathindex, operation*);
static void  select_child(json_array& refvalue, const char* path2, size_t pathindex, operation*);


enum str_to_num_error
{
  eSuccess,
  eInvalid,
  eOverflow
};

template<typename T>
static T string_to_unsigned(const char* p, str_to_num_error* errptr)
{
  T result = 0;
  str_to_num_error err = eSuccess;
  register unsigned char c;

  T MAX = std::numeric_limits< T >::max();
  T MAXDIV10 = MAX/10;

  if (p==0 || *p=='\0' || (*p=='0' && *(p+1)!='\0'))
  {
    err = eInvalid;
  }
  else
  {
    for (c = *p; err == eSuccess && *p; c = *++p)
    {
      c -= '0';

      if (c < 10)
      {
        if (result > MAXDIV10) err = eOverflow;
        result *= 10;

        if (c > (MAX - result) ) err = eOverflow;
        result += c;
      }
      else
        err = eInvalid;
    }
  }

  *errptr = err;
  return (err == eSuccess)?result : 0;
}


static size_t json_pointer_str_to_index(const char* p, size_t path_index)
{
  str_to_num_error errptr;
  size_t result = string_to_unsigned<size_t>(p, &errptr);

  if (errptr!=eSuccess)
    throw pointer_fail("string to int fail", path_index);

  return result;
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


void select_child(json_object& refvalue, const char* path, size_t pathindex,
                  operation* op)
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

  if (next_delim)
  {
    if (it != refvalue.end())
    {
      if (it->second.is_array())
        select_child(it->second.as_array(), next_delim+1, pathindex+1, op);
      else if (it->second.is_object())
        select_child(it->second.as_object(), next_delim+1, pathindex+1, op);
      else
        throw pointer_fail("pointer cannot continue, value selected in object is not a container", pathindex);
    }
    else
      throw pointer_fail("pointer cannot continue, object does not contain name", pathindex);
  }
  else
  {
    if (it != refvalue.end())
    {
      json_value & self = it->second;
      switch (op->action)
      {
        case operation::eAdd :
        {
          if (op->read_only)
          {
            self = *op->read_only;  // create a copy
          }
          else
          {
            self.swap( op->temp );
          }
//          op->target = &self;
          break;
        }
        case operation::eReplace :
        {
          self = *(op->read_only);
          break;
        }
        case operation::eRemove :
        {
          refvalue.erase( it );
          break;
        }
        case operation::eCut :
        {
          op->temp.swap( self );
          refvalue.erase( it );
          break;
        }
        case operation::eRead :
        {
          op->read_only = &self;
          break;
        }
        case operation::operation::eTest:
        {
          if (self != *op->read_only)
            throw std::runtime_error("test operation failed");// TODO: use patch exception
          break;
        }

      }
    }
    else
    {
      switch (op->action)
      {
        case operation::eAdd :
        {
          std::pair<json_object::iterator, bool> r;
          if (op->read_only)
          {
            r = refvalue.insert(std::make_pair(token, *(op->read_only)));
          }
          else
          {
            r = refvalue.insert(std::make_pair(token, json_value::make_null()));
            r.first->second.swap( op->temp );
          }
//          op->target = &(r.first->second);
          break;
        }
        default: throw pointer_fail("name not present in object", pathindex);
      }
    }
  }
}

static void select_child(json_array& refvalue, const char* path,
                         size_t pathindex,
                         operation* op)
{
  const char* next_delim = strchr(path, JPDELIM);

  std::string token = next_delim? std::string(path, next_delim-path) : path;
  size_t index = (token=="-")? refvalue.size() : json_pointer_str_to_index(token.c_str(), pathindex);



  if (next_delim)
  {
    if (index < refvalue.size() )
    {
      if (refvalue[index].is_array())
        select_child(refvalue[index].as_array(), next_delim+1, pathindex+1, op);
      else if (refvalue[index].is_object())
        select_child(refvalue[index].as_object(), next_delim+1, pathindex+1, op);
      else
      {
        throw pointer_fail("value selected in array is not a container", pathindex);
      }
    }
    else
      throw pointer_fail("index not present in array", pathindex);
  }
  else
  {
    if (index < refvalue.size() )
    {
      json_value & self = refvalue[index];
      switch (op->action)
      {
        case operation::eAdd :
        {
          if (op->read_only)
          {
            refvalue.insert( refvalue.begin() + index,  *(op->read_only)); // create a copy
          }
          else
          {
            refvalue.insert( refvalue.begin() + index,  json_value::make_null());
            refvalue[index].swap( op->temp );
          }
//          op->target = & refvalue[index];
          break;
        }
        case operation::eReplace :
        {
          self = *(op->read_only);
          break;
        }
        case operation::eRemove :
        {
          refvalue.erase( refvalue.begin() + index );
          break;
        }
        case operation::eCut :
        {
          op->temp.swap( self );
          refvalue.erase( refvalue.begin() + index );
          break;
        }
        case operation::eRead :
        {
          op->read_only = &self;
          break;
        }
        case operation::operation::eTest:
        {
          if (self != *op->read_only)
            throw std::runtime_error("test failed"); // TODO: use patch exception
          break;
        }
      }
    }
    else
    {
      switch (op->action)
      {
        case operation::eAdd :
        {
          if (index == refvalue.size())
          {
            if (op->read_only)
            {
              refvalue.push_back( *(op->read_only) ); // create a copy
            }
            else
            {
              refvalue.push_back( json_value::make_null() );  // swap
              refvalue[index].swap( op->temp );
            }
//            op->target = &refvalue[index];
            return;
          }
        }
        default: throw pointer_fail("index not present in array", pathindex);
      }
    }
  }
}


void resolve(json_value& root,
             const std::string& __path,
             struct operation* op)
{
  const char* path = __path.c_str();

  switch (*path)
  {
    case '\0' :
    {
      switch (op->action)
      {
        case operation::eReplace:
        {
          root = *(op->read_only);
          break;
        }
        case operation::eAdd :
        {
          if (op->read_only)
            root = *op->read_only;
          else
            root.swap( op->temp );
          break;
        }
        case operation::eRemove :
        {
          root = json_value::make_null();
          break;
        }
        case operation::eRead :
        {
          op->read_only = &root;
          break;
        }
        case operation::eCut :
        {
          op->temp.swap( root );
          break;
        }
        case operation::operation::eTest:
        {
          if (root != *op->read_only)
            throw std::runtime_error("test failed");
          break;
        }
      }
      return;
    }
    case JPDELIM :
    {
      if (root.is_array())
      {
        select_child(root.as_array(),  path+1 , 0, op);
      }
      else if (root.is_object())
      {
        select_child(root.as_object(), path+1, 0, op);
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


void apply_patch(json_value& doc,
                 const json_array& patch)
{
  for (json_array::const_iterator it = patch.begin();
       it != patch.end(); ++it)
  {
    const json_object & cur_operation = it->as_object();
    json_string op = get_or_throw(cur_operation, "op").as_string();
    const std::string& path = get_or_throw(cur_operation, "path").as_string();
    if (op == "add")
    {
      // TODO: if source patch is non-const, use the temp variable
      // new item, MOVE possible, otherwise copy
      operation op(operation::eAdd);
      op.read_only = &get_or_throw(cur_operation, "value");
      resolve(doc, path, &op);
    }
    else if (op == "remove")
    {
      operation op(operation::eRemove);
      resolve(doc, path, &op);
    }
    else if (op == "replace")
    {
      // TODO: can MOVE if a non-const was passed in
      operation op(operation::eReplace);
      op.read_only = &get_or_throw(cur_operation, "value");
      resolve(doc, path, &op);
    }
    else if (op == "move")
    {
      const std::string& from = get_or_throw(cur_operation, "from").as_string();
      if (from != path)
      {
        // first the eCut swaps the 'from' value into temp, and then later that is
        // swapped into the value at 'path'
        operation op(operation::eCut);
        resolve(doc, from, &op);

        op.action = operation::eAdd;
        resolve(doc, path, &op);
      }
    }
    else if (op == "copy")
    {
      const std::string& from = get_or_throw(cur_operation, "from").as_string();
      if (from != path)
      {
        operation op(operation::eRead);
        resolve(doc, from, &op);

        op.action = operation::eAdd;
        resolve(doc, path, &op);
      }
    }
    else if (op == "test")
    {
      operation op(operation::eTest);
      op.read_only = &get_or_throw(cur_operation, "value");
      resolve(doc, path, &op);
    }
    else
    {
      // TODO: throw bad_patch
      throw std::runtime_error("invalid patch op code");
    }
  }
}

}
