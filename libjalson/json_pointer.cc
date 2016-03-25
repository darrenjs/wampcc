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

namespace opcode
{
  enum value
  {
    eAdd,
    eReplace,
    eRemove,
    eRead,
    eCut,     /* delete and keep a copy */
    eTest
  };
}


struct const_variant
{
  typedef const json_value value_type;
  typedef const json_array array_type;
  typedef const json_object object_type;
  typedef json_object::const_iterator iterator;
};

struct nonconst_variant
{
  typedef json_value value_type;
  typedef json_array array_type;
  typedef json_object object_type;
  typedef json_object::iterator iterator;
};


struct operation
{
  opcode::value action;

  const json_value * read_only;
  json_value temp;

  operation(opcode::value op)
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
        case opcode::eAdd :
        {
          if (op->read_only)
          {
            self = *op->read_only;  // create a copy
          }
          else
          {
            self.swap( op->temp );
          }
          break;
        }
        case opcode::eReplace :
        {
          self = *(op->read_only);
          break;
        }
        case opcode::eRemove :
        {
          refvalue.erase( it );
          break;
        }
        case opcode::eCut :
        {
          op->temp.swap( self );
          refvalue.erase( it );
          break;
        }
        case opcode::eRead :
        {
          op->read_only = &self;
          break;
        }
        case opcode::eTest:
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
        case opcode::eAdd :
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
        case opcode::eAdd :
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
          break;
        }
        case opcode::eReplace :
        {
          self = *(op->read_only);
          break;
        }
        case opcode::eRemove :
        {
          refvalue.erase( refvalue.begin() + index );
          break;
        }
        case opcode::eCut :
        {
          op->temp.swap( self );
          refvalue.erase( refvalue.begin() + index );
          break;
        }
        case opcode::eRead :
        {
          op->read_only = &self;
          break;
        }
        case opcode::eTest:
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
        case opcode::eAdd :
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
        case opcode::eReplace:
        {
          root = *(op->read_only);
          break;
        }
        case opcode::eAdd :
        {
          if (op->read_only)
            root = *op->read_only;
          else
            root.swap( op->temp );
          break;
        }
        case opcode::eRemove :
        {
          root = json_value::make_null();
          break;
        }
        case opcode::eRead :
        {
          op->read_only = &root;
          break;
        }
        case opcode::eCut :
        {
          op->temp.swap( root );
          break;
        }
        case opcode::eTest:
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


const json_string & get_field_str(const json_object& cur_operation, const char* fieldname, int patch_index)
{
  json_object::const_iterator it = cur_operation.find( fieldname );
  if (it == cur_operation.end() || !it->second.is_string())
  {
    throw bad_patch("invalid patch operation", patch_index);
  }
  return it->second.as_string();
}

const json_value * get_value(const json_object& cur_operation, int patch_index)
{
  json_object::const_iterator it = cur_operation.find( "value" );
  if (it == cur_operation.end())
  {
    throw bad_patch("missing 'value'", patch_index);
  }
  return &it->second;
}

void apply_patch(json_value& doc,
                 const json_array& patch)
{
  // Take a copy, which we will use to restore the source document if there is
  // an error when applying the patch.  There are more efficient approaches that
  // we could use here, e.g., copy on write, or accumulation of reverse patches.
  json_value copy = doc;
  size_t patch_index = 0;
  try
  {
    for (json_array::const_iterator it = patch.begin();
         it != patch.end(); ++it, ++patch_index)
    {
      if (!it->is_object())
        throw bad_patch("operation must be a JSON object", patch_index);

      const json_object & cur_operation = it->as_object();

      const json_string& op = get_field_str(cur_operation, "op", patch_index);
      const json_string& path = get_field_str(cur_operation, "path", patch_index);

      if (op == "add")
      {
        // TODO: if source patch is non-const, use the temp variable
        // new item, MOVE possible, otherwise copy
        operation op(opcode::eAdd);
        op.read_only = get_value(cur_operation, patch_index);
        resolve(doc, path, &op);
      }
      else if (op == "remove")
      {
        operation op(opcode::eRemove);
        resolve(doc, path, &op);
      }
      else if (op == "replace")
      {
        // TODO: can MOVE if a non-const was passed in
        operation op(opcode::eReplace);
        op.read_only = get_value(cur_operation, patch_index);
        resolve(doc, path, &op);
      }
      else if (op == "move")
      {
        const std::string& from = get_field_str(cur_operation, "from", patch_index);
        if (from != path)
        {
          // first the eCut swaps the 'from' value into temp, and then later that is
          // swapped into the value at 'path'
          operation op(opcode::eCut);
          resolve(doc, from, &op);

          op.action = opcode::eAdd;
          resolve(doc, path, &op);
        }
      }
      else if (op == "copy")
      {
        const std::string& from = get_field_str(cur_operation, "from", patch_index);
        if (from != path)
        {
          operation op(opcode::eRead);
          resolve(doc, from, &op);

          op.action = opcode::eAdd;
          resolve(doc, path, &op);
        }
      }
      else if (op == "test")
      {
        operation op(opcode::eTest);

        op.read_only = get_value(cur_operation, patch_index);
        resolve(doc, path, &op);
      }
      else
      {
        throw bad_patch("invalid patch op member", patch_index);
      }
    }
  }
  catch (...)
  {
    doc.swap(copy);
    throw;
  }
}

}
