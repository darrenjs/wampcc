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
  };

  opcode action;
  const json_value * source;
  json_value * output;
  json_value * move_target;
  json_value * target;
  json_value value;

  operation(opcode op)
  : action(op),
    source(0),
    output(0)
  {
  }
};


static void  select_child(json_object& refvalue, const char* path2, size_t pathindex, operation*);
static void  select_child(json_array& refvalue, const char* path2, size_t pathindex, operation*);




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
          self.swap( op->value );
          op->target = &self;
          break;
        }
        case operation::eReplace :
        {
          self = *(op->source);
          break;
        }
        case operation::eRemove :
        {
          refvalue.erase( it );
          break;
        }
        case operation::eCut :
        {
          op->value.swap( self );
          refvalue.erase( it );
          break;
        }
        case operation::eRead :
        {
          op->source = &self;
          break;
        }
        case operation::operation::eTest:
        {
          if (self != *op->source)
            throw std::runtime_error("test operation failed");
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
//          std::pair<json_object::iterator, bool> r = refvalue.insert(std::make_pair(token, *(op->source)));
          std::pair<json_object::iterator, bool> r = refvalue.insert(std::make_pair(token, json_value::make_null()));
          r.first->second.swap( op->value );
          op->target = &(r.first->second);
          break;
        }

        default:
        {
          throw pointer_fail("name not present in object", pathindex);
        }
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
  size_t index = (token=="-")? refvalue.size() : json_pointer_str_to_index(token.c_str());

  if (index < refvalue.size() )
  {

    if (next_delim)
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
    {
      json_value & self = refvalue[index];
      switch (op->action)
      {
        case operation::eAdd :
        {
//          refvalue.insert( refvalue.begin() + index,  *(op->source));
          refvalue.insert( refvalue.begin() + index,  json_value::make_null());
          refvalue[index].swap( op->value );
          op->target = & refvalue[index];
          break;
        }
        case operation::eReplace :
        {
          self = *(op->source);
          break;
        }
        case operation::eRemove :
        {
          refvalue.erase( refvalue.begin() + index );
          break;
        }
        case operation::eCut :
        {
          op->value.swap( self );
          refvalue.erase( refvalue.begin() + index );
          break;
        }
        case operation::eRead :
        {
          op->source = &self;
          break;
        }
        case operation::operation::eTest:
        {
          if (self != *op->source)
            throw std::runtime_error("test failed");
          break;
        }
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
//          refvalue.push_back( *(op->source) );
          refvalue.push_back( json_value::make_null() );
          refvalue[index].swap( op->value );
          op->target = &refvalue[index];
          return;
        }
        break;
      }
      default:
        break;
    }
    throw pointer_fail("index not present in array", pathindex);
  }
}


void resolve(json_value& root,
             const std::string& path,
             struct operation* op)
{
  const char* path2 = path.c_str();

  switch (*path2)
  {
    case '\0' :
    {
      // empty string , which implies the full document
      // TODO: need to apply operation here

      switch (op->action)
      {
        case operation::eReplace:
        case operation::eAdd :
        {
          root.swap( op->value );
          break;
        }
        case operation::eRemove :
        {
          root = json_value::make_null();
          break;
        }
        case operation::eRead :
        {
          op->source = &root;
          break;
        }
        case operation::eCut :
        {
          op->value.swap( root  );
          break;
        }
        case operation::operation::eTest:
        {
          if (root != *op->source)
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
        select_child(root.as_array(),  path2+1 , 0, op);
      }
      else if (root.is_object())
      {
        select_child(root.as_object(), path2+1, 0, op);
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
    if (op == "add")
    {
      operation op(operation::eAdd);
      op.value = get_or_throw(cur_operation, "value");
//      op.source = &get_or_throw(cur_operation, "value");
      resolve(doc,get_or_throw(cur_operation, "path").as_string(), &op);
    }
    else if (op == "remove")
    {
      operation op(operation::eRemove);
      resolve(doc,get_or_throw(cur_operation, "path").as_string(), &op);
    }
    else if (op == "replace")
    {
      operation op(operation::eReplace);
      op.source = &get_or_throw(cur_operation, "value");
      resolve(doc,get_or_throw(cur_operation, "path").as_string(), &op);
    }
    else if (op == "move")
    {
      operation op(operation::eCut);
      resolve(doc, get_or_throw(cur_operation, "from").as_string(), &op);

      op.action = operation::eAdd;
      resolve(doc, get_or_throw(cur_operation, "path").as_string(), &op);
    }
    else if (op == "copy")
    {
      operation op(operation::eRead);
      resolve(doc,get_or_throw(cur_operation, "from").as_string(), &op);

      op.action = operation::eAdd;
      op.value  = *(op.source);
      resolve(doc, get_or_throw(cur_operation, "path").as_string(), &op);
    }
    else if (op == "test")
    {
      operation op(operation::eTest);
      op.source = &get_or_throw(cur_operation, "value");
      resolve(doc,get_or_throw(cur_operation, "path").as_string(), &op);
    }
    else
    {
      // TODO: throw bad_patch
      throw std::runtime_error("invalid patch op code");
    }
  }
}

}
