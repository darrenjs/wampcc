/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/json.h"

#include <limits>

#include <string.h>
#include <stdlib.h>

/*

This file contains an implementation of:

    JavaScript Object Notation (JSON) Pointer (IETF RFC 6901)
    JavaScript Object Notation (JSON) Patch   (IETF RFC 6902)

 */



#define JPDELIM '/'

namespace wampcc {

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


template<typename T>
struct operation
{
  opcode::value action;

  const json_value * read_only;
  typename T::value_type * output;
  json_value temp;
  size_t path_index;

  operation(opcode::value op)
    : action(op),
      read_only(0),
      output(0),
      path_index(0)

  {
  }
};


// template<typename T>
// static void  select_child(json_object& refvalue, const char* path2, size_t pathindex, operation<T>*);

// template<typename T>
// static void  select_child(json_array& refvalue, const char* path2, size_t pathindex, operation<T>*);


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

  if (errptr==eSuccess)
    return result;
  else
    throw bad_pointer("cannot convert string to integer", path_index);
}


static const char* has_escape_seq(const char* p, const char* end)
{
  for (; p < end; p++)
  {
    p = strchr(p, '~');
    if (!p) return 0;

    if ( ( p+1 < end) && (*(p+1) =='0' || *(p+1)=='1') ) return p;
  }
  return 0;
}


static char* expand_str(const char* start, const char *end)
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


// template<typename T>
// void select_child(json_object& refvalue, const char* path, size_t pathindex,
//                   operation<T>* op)
// {
//   const char* next_delim = strchr(path, JPDELIM);

//   std::string token = next_delim? std::string(path, next_delim-path) : path;
//   const char * escaped = has_escape_seq(path, (next_delim)? next_delim : path+strlen(path));
//   if (escaped)
//   {
//     char *  copy = expand_str( path, (next_delim)? next_delim : path+strlen(path));
//     token = copy;
//     delete [] copy;
//   }

//   json_object::iterator it = refvalue.find( token );

//   if (next_delim)
//   {
//     if (it != refvalue.end())
//     {
//       if (it->second.is_array())
//         select_child(it->second.as_array(), next_delim+1, pathindex+1, op);
//       else if (it->second.is_object())
//         select_child(it->second.as_object(), next_delim+1, pathindex+1, op);
//       else
//         throw bad_pointer("pointer cannot continue, value selected in object is not a container", pathindex);
//     }
//     else
//       throw bad_pointer("pointer cannot continue, object does not contain name", pathindex);
//   }
//   else
//   {
//     if (it != refvalue.end())
//     {
//       json_value & self = it->second;
//       switch (op->action)
//       {
//         case opcode::eAdd :
//         {
//           if (op->read_only)
//           {
//             self = *op->read_only;  // create a copy
//           }
//           else
//           {
//             self.swap( op->temp );
//           }
//           break;
//         }
//         case opcode::eReplace :
//         {
//           self = *(op->read_only);
//           break;
//         }
//         case opcode::eRemove :
//         {
//           refvalue.erase( it );
//           break;
//         }
//         case opcode::eCut :
//         {
//           op->temp.swap( self );
//           refvalue.erase( it );
//           break;
//         }
//         case opcode::eRead :
//         {
//           op->read_only = &self;
//           break;
//         }
//         case opcode::eTest:
//         {
//           if (self != *op->read_only)
//             throw std::runtime_error("test operation failed");// TODO: use patch exception
//           break;
//         }

//       }
//     }
//     else
//     {
//       switch (op->action)
//       {
//         case opcode::eAdd :
//         {
//           std::pair<json_object::iterator, bool> r;
//           if (op->read_only)
//           {
//             r = refvalue.insert(std::make_pair(token, *(op->read_only)));
//           }
//           else
//           {
//             r = refvalue.insert(std::make_pair(token, json_value::make_null()));
//             r.first->second.swap( op->temp );
//           }
//           break;
//         }
//         default: throw bad_pointer("name not present in object", pathindex);
//       }
//     }
//   }
// }

// template<typename T>
// static void select_child(json_array& refvalue, const char* path,
//                          size_t pathindex,
//                          operation<T>* op)
// {
//   const char* next_delim = strchr(path, JPDELIM);

//   std::string token = next_delim? std::string(path, next_delim-path) : path;
//   size_t index = (token=="-")? refvalue.size() : json_pointer_str_to_index(token.c_str(), pathindex);



//   if (next_delim)
//   {
//     if (index < refvalue.size() )
//     {
//       if (refvalue[index].is_array())
//         select_child(refvalue[index].as_array(), next_delim+1, pathindex+1, op);
//       else if (refvalue[index].is_object())
//         select_child(refvalue[index].as_object(), next_delim+1, pathindex+1, op);
//       else
//       {
//         throw bad_pointer("value selected in array is not a container", pathindex);
//       }
//     }
//     else
//       throw bad_pointer("index not present in array", pathindex);
//   }
//   else
//   {
//     if (index < refvalue.size() )
//     {
//       json_value & self = refvalue[index];
//       switch (op->action)
//       {
//         case opcode::eAdd :
//         {
//           if (op->read_only)
//           {
//             refvalue.insert( refvalue.begin() + index,  *(op->read_only)); // create a copy
//           }
//           else
//           {
//             refvalue.insert( refvalue.begin() + index,  json_value::make_null());
//             refvalue[index].swap( op->temp );
//           }
//           break;
//         }
//         case opcode::eReplace :
//         {
//           self = *(op->read_only);
//           break;
//         }
//         case opcode::eRemove :
//         {
//           refvalue.erase( refvalue.begin() + index );
//           break;
//         }
//         case opcode::eCut :
//         {
//           op->temp.swap( self );
//           refvalue.erase( refvalue.begin() + index );
//           break;
//         }
//         case opcode::eRead :
//         {
//           op->read_only = &self;
//           break;
//         }
//         case opcode::eTest:
//         {
//           if (self != *op->read_only)
//             throw std::runtime_error("test failed"); // TODO: use patch exception
//           break;
//         }
//       }
//     }
//     else
//     {
//       switch (op->action)
//       {
//         case opcode::eAdd :
//         {
//           if (index == refvalue.size())
//           {
//             if (op->read_only)
//             {
//               refvalue.push_back( *(op->read_only) ); // create a copy
//             }
//             else
//             {
//               refvalue.push_back( json_value::make_null() );  // swap
//               refvalue[index].swap( op->temp );
//             }
//             return;
//           }
//         }
//         default: throw bad_pointer("index not present in array", pathindex);
//       }
//     }
//   }
// }


// template<typename T>
// void resolve(json_value& root,
//              const std::string& __path,
//              struct operation<T>* op)
// {
//   const char* path = __path.c_str();

//   switch (*path)
//   {
//     case '\0' :
//     {
//       switch (op->action)
//       {
//         case opcode::eReplace:
//         {
//           root = *(op->read_only);
//           break;
//         }
//         case opcode::eAdd :
//         {
//           if (op->read_only)
//             root = *op->read_only;
//           else
//             root.swap( op->temp );
//           break;
//         }
//         case opcode::eRemove :
//         {
//           root = json_value::make_null();
//           break;
//         }
//         case opcode::eRead :
//         {
//           op->read_only = &root;
//           break;
//         }
//         case opcode::eCut :
//         {
//           op->temp.swap( root );
//           break;
//         }
//         case opcode::eTest:
//         {
//           if (root != *op->read_only)
//             throw std::runtime_error("test failed");
//           break;
//         }
//       }
//       return;
//     }
//     case JPDELIM :
//     {
//       if (root.is_array())
//       {
//         select_child(root.as_array(),  path+1 , 0, op);
//       }
//       else if (root.is_object())
//       {
//         select_child(root.as_object(), path+1, 0, op);
//       }
//       else
//       {
//         throw bad_pointer("root item not a container", 0);
//       }
//       break;
//     }
//     default :
//     {
//       throw bad_pointer("string is not a invalid pointer", 0);
//     }
//   }

// }


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

// void apply_patch_old(json_value& doc,
//                  const json_array& patch)
// {
//   // Take a copy, which we will use to restore the source document if there is
//   // an error when applying the patch.  There are more efficient approaches that
//   // we could use here, e.g., copy on write, or accumulation of reverse patches.
//   json_value copy = doc;
//   size_t patch_index = 0;
//   try
//   {
//     for (json_array::const_iterator it = patch.begin();
//          it != patch.end(); ++it, ++patch_index)
//     {
//       if (!it->is_object())
//         throw bad_patch("operation must be a JSON object", patch_index);

//       const json_object & cur_operation = it->as_object();

//       const json_string& op = get_field_str(cur_operation, "op", patch_index);
//       const json_string& path = get_field_str(cur_operation, "path", patch_index);

//       if (op == "add")
//       {
//         // TODO: if source patch is non-const, use the temp variable
//         // new item, MOVE possible, otherwise copy
//         operation<nonconst_variant> op(opcode::eAdd);
//         op.read_only = get_value(cur_operation, patch_index);
//         resolve(doc, path, &op);
//       }
//       else if (op == "remove")
//       {
//         operation<nonconst_variant> op(opcode::eRemove);
//         resolve(doc, path, &op);
//       }
//       else if (op == "replace")
//       {
//         // TODO: can MOVE if a non-const was passed in
//         operation<nonconst_variant> op(opcode::eReplace);
//         op.read_only = get_value(cur_operation, patch_index);
//         resolve(doc, path, &op);
//       }
//       else if (op == "move")
//       {
//         const std::string& from = get_field_str(cur_operation, "from", patch_index);
//         if (from != path)
//         {
//           // first the eCut swaps the 'from' value into temp, and then later that is
//           // swapped into the value at 'path'
//           operation<nonconst_variant> op(opcode::eCut);
//           resolve(doc, from, &op);

//           op.action = opcode::eAdd;
//           resolve(doc, path, &op);
//         }
//       }
//       else if (op == "copy")
//       {
//         const std::string& from = get_field_str(cur_operation, "from", patch_index);
//         if (from != path)
//         {
//           operation<nonconst_variant> op(opcode::eRead);
//           resolve(doc, from, &op);

//           op.action = opcode::eAdd;
//           resolve(doc, path, &op);
//         }
//       }
//       else if (op == "test")
//       {
//         operation<nonconst_variant> op(opcode::eTest);

//         op.read_only = get_value(cur_operation, patch_index);
//         resolve(doc, path, &op);
//       }
//       else
//       {
//         throw bad_patch("invalid patch op member", patch_index);
//       }
//     }
//   }
//   catch (...)
//   {
//     doc.swap(copy);
//     throw;
//   }
// }

struct read_operation
{
  template<typename T>
  static bool operate_on_target(typename T::value_type& target,
                                operation<T>* op)
  {
    op->output = &target;
    return true;
  }


  template<typename T>
  static bool operate_on_object(typename T::object_type & container,
                                const std::string& token,
                                operation<T>* op)
  {
    typename T::iterator it = container.find( token );
    if (it != container.end())
      return operate_on_target(it->second, op);
    else
      return false;
  }


  template<typename T>
  static bool operate_on_array(typename T::array_type & container,
                               size_t i,
                               operation<T>* op)
  {
    if (i < container.size() )
      return operate_on_target(container[i], op);
    else
      return false;
  }
};


// only applied on non-const targets
struct patch_operation
{

  template<typename T>
  static bool operate_on_target(json_value& target,
                                operation<T>* op)
  {
    switch (op->action)
    {
      case opcode::eAdd :
      {
        if (op->read_only)
          target = *op->read_only;  // create a copy
        else
          target.swap( op->temp );
        break;
      }
      case opcode::eReplace :
      {
        target = *(op->read_only);
        break;
      }
      case opcode::eRemove :
      {
        break;
      }
      case opcode::eCut :
      {
        op->temp.swap( target );
        break;
      }
      case opcode::eRead :
      {
        op->read_only = &target;
        break;
      }
      case opcode::eTest:
      {
        if (target != *op->read_only) return false;
      }
    }
    return true;
  }


  template<typename T>
  static bool operate_on_object(json_object& container,
                                const std::string& token,
                                operation<T>* op)
  {
    json_object::iterator it = container.find( token );
    if (it != container.end())
    {
      return patch_operation::operate(container, it->second, it, op);
    }
    else if (op->action == opcode::eAdd)
    {
      std::pair<json_object::iterator, bool> r;
      if (op->read_only)
      {
        r = container.insert(std::make_pair(token, *(op->read_only)));
      }
      else
      {
        r = container.insert(std::make_pair(token, json_value::make_null()));
        r.first->second.swap( op->temp );
      }
      return true;
    }
    else
      return false;
  }


  template<typename T>
  static bool operate_on_array(json_array& container,
                               size_t index,
                               operation<T>* op)
  {
    if (index < container.size() )
    {
      if (op->action == opcode::eAdd)
      {
        if (op->read_only)
        {
          container.insert( container.begin() + index,  *(op->read_only)); // create a copy
        }
        else
        {
          container.insert( container.begin() + index,  json_value::make_null());
          container[index].swap( op->temp );
        }
        return true;
      }
      else
      {
        return patch_operation::operate(container, container[index], container.begin()+index, op);
      }
    }
    else if (index == container.size() && op->action==opcode::eAdd)
    {
      if (op->read_only)
      {
        container.push_back( *(op->read_only) ); // create a copy
      }
      else
      {
        container.push_back( json_value::make_null() );  // swap
        container[index].swap( op->temp );
      }
      return true;
    }
    else
      return false;
  }

private:
  template<typename P, typename I, typename T>
  static bool operate(P& container,
                      json_value& self,
                      I iter,
                      operation<T>* op)
  {
    // first operate on the target
    if (patch_operation::operate_on_target(self, op) == false) return false;

    // now also operate on the container of the target
    switch (op->action)
    {
      case opcode::eRemove :
      case opcode::eCut :
      {
        container.erase( iter );
        break;
      }
      default: break;
    }
    return true;
  }
};




// forward references
template <typename F, typename T>
static bool resolve_path_on_object(typename T::object_type & refvalue,
                                   const char* path,
                                   operation<T>* op);
template <typename F, typename T>
static bool resolve_path_on_array(typename T::array_type & refvalue,
                                  const char* path,
                                  operation<T>* op);

template <typename F, typename T>
static bool resolve_path_on_object(typename T::object_type & refvalue,
                                   const char* path,
                                   operation<T>* op)
{
  op->path_index++;
  const char* next_delim = strchr(path, JPDELIM);

  // TODO: improve memory usage here
  std::string token = next_delim? std::string(path, next_delim-path) : path;
  const char * escaped = has_escape_seq(path, (next_delim)? next_delim : path+strlen(path));

  if (escaped)
  {
    // TODO: improve memory usage here
    char *  copy = expand_str( path, (next_delim)? next_delim : path+strlen(path));
    token = copy;
    delete [] copy;
  }

  if (next_delim)
  {
    typename T::iterator it = refvalue.find( token );
    if (it != refvalue.end())
    {
      if (it->second.is_array())
        return resolve_path_on_array<F>(it->second.as_array(), next_delim+1, op);
      else if (it->second.is_object())
        return resolve_path_on_object<F>(it->second.as_object(), next_delim+1, op);
    }
  }
  else
  {
    return F::operate_on_object(refvalue, token, op);
  }

  return false;
}


template <typename F, typename T>
static bool resolve_path_on_array(typename T::array_type & refvalue,
                                  const char* path,
                                  operation<T>* op)
{
  op->path_index++;
  const char* next_delim = strchr(path, JPDELIM);

  std::string token = next_delim? std::string(path, next_delim-path) : path;
  size_t index = (token=="-")? refvalue.size() : json_pointer_str_to_index(token.c_str(), op->path_index);

  if (next_delim)
  {
    if (index < refvalue.size() )
    {
      if (refvalue[index].is_array())
        return resolve_path_on_array<F>(refvalue[index].as_array(), next_delim+1, op);
      if (refvalue[index].is_object())
        return resolve_path_on_object<F>(refvalue[index].as_object(), next_delim+1, op);
    }
  }
  else
  {
    return F::operate_on_array(refvalue, index, op);
  }

  return false;
}

template <typename F, typename T>
static bool resolve_path_from_root(typename T::value_type& root,
                                   const std::string& __path,
                                   operation<T>* op)
{
  const char* path = __path.c_str();

  if (*path == '\0')
  {
    return F::operate_on_target(root, op);
  }
  else if (*path == JPDELIM )
  {
    if (root.is_array())
      return resolve_path_on_array<F>(root.as_array(),  path+1 , op);
    if (root.is_object())
     return resolve_path_on_object<F>(root.as_object(), path+1, op);
  }
  else
    throw bad_pointer("invalid pointer syntax", 0);

  return false;
}


template<typename T>
bool  apply_single_patch(json_value& doc,
                      const std::string& path,
                      operation<T>* op)
{
  return resolve_path_from_root<patch_operation, nonconst_variant>(
    doc,
    path,
    op);
}

const json_value * eval_json_pointer(const json_value& doc,
                                     const char* path)
{
  operation< const_variant > op(opcode::eRead);

  resolve_path_from_root<read_operation, const_variant>(
    doc,
    std::string(path),
    &op);

  return op.output;
}


json_value * eval_json_pointer(json_value& doc,
                               const char* path)
{
  operation< nonconst_variant > op(opcode::eRead);

  resolve_path_from_root<read_operation, nonconst_variant>(
    doc,
    std::string(path),
    &op);

  return op.output;
}



bool apply_patch(json_value& doc,
                 const json_array& patch)
{
  // Take a copy, which we will use to restore the source document if there is
  // an error when applying the patch.  There are more efficient approaches that
  // we could use here, e.g., copy on write, or accumulation of reverse patches.
  json_value copy = doc;
  size_t patch_index = 0;
  bool patch_ok = true;

  try
  {
    for (json_array::const_iterator it = patch.begin();
         it != patch.end() && patch_ok; ++it, ++patch_index)
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
        operation<nonconst_variant> op(opcode::eAdd);
        op.read_only = get_value(cur_operation, patch_index);
        patch_ok = apply_single_patch(doc, path, &op);
      }
      else if (op == "remove")
      {
        operation<nonconst_variant> op(opcode::eRemove);
        patch_ok =  apply_single_patch(doc, path, &op);
      }
      else if (op == "replace")
      {
        // TODO: can MOVE if a non-const was passed in
        operation<nonconst_variant> op(opcode::eReplace);
        op.read_only = get_value(cur_operation, patch_index);
        patch_ok =  apply_single_patch(doc, path, &op);
      }
      else if (op == "move")
      {
        const std::string& from = get_field_str(cur_operation, "from", patch_index);
        if (from != path)
        {
          // first the eCut swaps the 'from' value into temp, and then later that is
          // swapped into the value at 'path'
          operation<nonconst_variant> op(opcode::eCut);
          patch_ok = apply_single_patch(doc, from, &op);

          if (patch_ok)
          {
            op.action = opcode::eAdd;
            patch_ok = apply_single_patch(doc, path, &op);
          }
        }
      }
      else if (op == "copy")
      {
        const std::string& from = get_field_str(cur_operation, "from", patch_index);
        if (from != path)
        {
          operation<nonconst_variant> op(opcode::eRead);
          patch_ok = apply_single_patch(doc, from, &op);

          if (patch_ok)
          {
            op.action = opcode::eAdd;
            patch_ok = apply_single_patch(doc, path, &op);
          }
        }
      }
      else if (op == "test")
      {
        operation<nonconst_variant> op(opcode::eTest);

        op.read_only = get_value(cur_operation, patch_index);
        patch_ok = apply_single_patch(doc, path, &op);
      }
      else
      {
        throw bad_patch("invalid patch op member", patch_index);
      }
    } // for

    if (!patch_ok) doc.swap(copy); // roll back change
    return patch_ok;
  }
  catch (...)
  {
    doc.swap(copy); // roll back changes
    throw;
  }
}

}
