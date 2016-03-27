/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __JALSON_H__
#define __JALSON_H__


#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#if __cplusplus >=201103L
#include <type_traits>
#endif

#include <stdint.h>

namespace jalson
{

/* Get details about the underlying JSON implementation */
struct vendor_details
{
  const char* vendor;
  int major_version;
  int minor_version;
  int micro_version;

  // determine if the underlying implementation supports unsigned integer types
  bool has_uint;

  // does underlying implementation support encoding of non object/array types
  bool has_encode_any;
};

void get_vendor_details(vendor_details*);


/*
Fundamental JSON types.

Note that the json Number type is broken down into to separate types, real and
integer.

Note there is not a separate True and False types.
*/

typedef enum
{
  eNULL = 0,
  eOBJECT,
  eARRAY,
  eSTRING,
  eBOOL,
  eREAL,
  eINTEGER
} JSONType;

/* Convert a JSONType to string representation */
const char* type_to_str(JSONType t);

// ======================================================================
//
// Exception classes
//
// ======================================================================

// exception base class
class json_error : public std::runtime_error
{
public:
  json_error(const std::string& msg);
  virtual ~json_error() throw() {}
};

class parse_error : public json_error
{
public:
  std::string error;
  std::string source;
  int line;
  int column;
  int position;

  parse_error(const std::string& msg);

  virtual ~parse_error() throw() {}
};

class out_of_range : public json_error
{
public:
  size_t requested;
  out_of_range(size_t __requested);
  virtual ~out_of_range() throw() {}
};

class field_not_found : public json_error
{
public:
  std::string field; // field that was requested
  field_not_found(const std::string& field);
  virtual ~field_not_found() throw() {}
};

class type_mismatch : public json_error
{
public:
  JSONType actual;     // type actual
  JSONType requested;  // type requested
  type_mismatch(JSONType actual, JSONType requested);
  virtual ~type_mismatch() throw() {}
};

// exception when handling a JSON Pointer
class bad_pointer : public json_error
{
public:
  size_t path_index;
  bad_pointer(const std::string&,
               size_t index);
};

// exception when handling a JSON Patch
class bad_patch : public json_error
{
public:
  size_t patch_index;
  bad_patch(const std::string&,
             size_t index);
};

// ======================================================================
//
// Container types
//
// JSON container types are just the usual STL types.
//
// ======================================================================

class json_value;
typedef std::vector<json_value>            json_array;
typedef std::map<std::string, json_value>  json_object;
typedef std::string                        json_string;

// ======================================================================
//
// Internal implementation, hidden away for readability of this header.
//
#include <jalson/jalson_internals.h>
//
// ======================================================================

/* Container for any JSON value */
class json_value
{
public:

  /* Constructors & assignment */

  json_value();  // creates null value

  json_value(int);
  json_value(long);
  json_value(long long);

  json_value(bool);
  json_value(double);
  json_value(const char*);
  json_value(const char*, size_t);
  json_value(const std::string&);
  json_value(const json_array&);
  json_value(const json_object&);

  /* WARNING: ensure the underlying implementation have uint capability before
   * using any of these. */
  json_value(unsigned int);
  json_value(unsigned long);
  json_value(unsigned long long);

  /* copy & assignment */

  json_value(const json_value&);
  json_value& operator=(const json_value&);

  /* equality */

  bool operator==(const json_value& rhs) const;
  bool operator!=(const json_value& rhs) const { return not this->operator==(rhs); }

  /* create various JSON types that have default value */

  static json_value make_null();
  static json_value make_array();
  static json_value make_object();
  static json_value make_string(const char* v = "");
  static json_value make_bool(bool v = false);
  static json_value make_int(long long v = 0);
  static json_value make_uint(unsigned long long v = 0);
  static json_value make_double(double v = 0.0);

  /* type query */

  JSONType type() const { return m_impl.json_type(); }

  void check_type(JSONType t) const; // throw type_mismatch if match fails

  bool is_object()    const { return this->type() == eOBJECT; }
  bool is_array()     const { return this->type() == eARRAY; }
  bool is_container() const { return this->type() == eARRAY || this->type() == eOBJECT; }

  bool is_string()  const { return this->type() == eSTRING; }
  bool is_bool()    const { return this->type() == eBOOL; }
  bool is_true()    const { return this->is_bool() && m_impl.as_bool_unchecked()==true; }
  bool is_false()   const { return this->is_bool() && m_impl.as_bool_unchecked()==false; }

  bool is_null()    const { return this->type() == eNULL; }

  bool is_number()  const  { return this->is_real() || this->is_integer(); }
  bool is_real()    const  { return this->type() == eREAL; }
  bool is_integer() const  { return this->type() == eINTEGER; }

  // int conversion can result in loss of value if actual type differs to
  // that requested
  bool is_sint()    const  { return this->is_integer() && m_impl.is_sint(); }
  bool is_uint()    const  { return this->is_integer() && m_impl.is_uint(); }

  /* access the value */

  bool                as_bool() const { return m_impl.as_bool(); }
  double              as_real() const { return m_impl.as_real(); }

  long long           as_sint() const { return m_impl.as_sint_repr(); }
  unsigned long long  as_uint() const { return m_impl.as_uint_repr(); }


  // Future expansion. Added sizeed-int support, including methods to check int
  // width. Do we need is_int / as_int etc.

  // as_int16
  // as_int32
  // as_int64

  // is_int16
  // is_int32
  // is_int64

  // as_int / is_int
  // as_long / is_long
  // as_longlong / is_longlong


  json_string&       as_string()       { return this->as<json_string>(); }
  const json_string& as_string() const { return this->as<json_string>(); }

  json_array&        as_array()       { return this->as<json_array>(); }
  const json_array&  as_array() const { return this->as<json_array>(); }

  json_object&       as_object()        { return this->as<json_object>(); }
  const json_object& as_object() const  { return this->as<json_object>(); }

  // utility methods if self holds an array
  json_value&        operator[](size_t i)       {  return this->as<json_array>()[i]; }
  const json_value&  operator[](size_t i) const {  return this->as<json_array>()[i]; }
  json_value&        at(size_t i)       {  return this->as<json_array>().at(i); }
  const json_value&  at(size_t i) const {  return this->as<json_array>().at(i); }

  // utility methods if self holds an object
  json_value&        operator[](const std::string& k) { return this->as<json_object>()[k];}


  // void   add(v);  add(k,v);    TODO

  // get  / get_default TODO


  // Checked conversion to json_array / json_string / json_object
  template<typename T> const T& as() const
  {
    ensure_type_is_json_container((T*)0);
    return m_impl.as<T>();
  }

  // Checked conversion to json_array / json_string / json_object
  template<typename T> T& as()
  {
    ensure_type_is_json_container((T*)0);
    return m_impl.as<T>();
  }

  void swap(json_value&);


  /* Apply a JSON Patch (IETF RFC 6902). Can throw bad_pointer and bad_patch. */
  void patch(const json_array&);

  /* Evaulate a JSON Pointer (IETF RFC 6902). Return a pointer to the value
   * identified by the JSON Pointer, or null if not found. If the JSON Pointer
   * has illegal syntax a bad_pointer exception is thrown.
   */
  const json_value * eval(const char* json_pointer) const;
  json_value *       eval(const char* json_pointer);

  // Prevent accidental initialisation of json_value from a pointer
#if __cplusplus >= 201103L
  template<typename T> json_value(const T*)
  {
    static_assert(sizeof(T)==0,
                  "json_value cannot be initialised from pointer");
  }
#else
private:
  template<typename T> json_value(const T*){}; /* no init from pointer */
#endif

private:

  /* These functions exist simply to check a type specifed during a
   * template-based call is one of the JSON classes. If a type is not one of
   * these classes, it will cause a compiler error. */
  static void ensure_type_is_json_container(json_array*)  {}
  static void ensure_type_is_json_container(json_string*) {}
  static void ensure_type_is_json_container(json_object*) {}

  internals::valueimpl  m_impl;

  friend json_array&  append_array  (jalson::json_array&);
  friend json_object& append_object (jalson::json_array&);
  friend json_object& insert_object (jalson::json_object&, const std::string&);
  friend json_array&  insert_array  (jalson::json_object&, const std::string&);
};

std::ostream& operator<<(std::ostream&, const json_value&);


/** Make a copy of 'src' and add to the aray */
template <typename T>
json_value& append(jalson::json_array& arr, const T& src)
{
  arr.push_back( json_value() );

  json_value& last = arr.back();
  json_value temp(src);
  last.swap(temp);

  return arr.back();
}


/* Append a new object or array to an array, and return the newly created
 * item */
json_object& append_object (json_array& c);
json_array&  append_array  (json_array& c);

/* Insert a new object or array to an object, and return the newly created
 * item */
json_object& insert_object(json_object&, const std::string& key);
json_array&  insert_array (json_object&, const std::string& key);

/* Utility methods for extracting a value from a container.  If not found,
 * throws json_error exceptions. */
      json_value& get_or_throw(      json_object& ob, const std::string& key);
const json_value& get_or_throw(const json_object& ob, const std::string& key);

      json_value& get_or_throw(      json_array& ob, size_t index);
const json_value& get_or_throw(const json_array& ob, size_t index);

json_value get(const json_object&, const std::string& key,
              const json_value & defValue = json_value());

json_value get(const json_array&, size_t index,
              const json_value & defValue = json_value());

/* Encode & decode functions */

/* Encode a JSON value into a JSON-text serialised representation. The JSON
 * value passed into this function should be either an Object or an Array.  This
 * is for conformance to RFC 4627. If you wish to encode other JSON types, then
 * try encode_any. */
std::string encode(const json_value& src);
std::string encode_any(const json_value& src);

/* Decode into 'dest' out parameters, which on legacy C++ reduces the amount of
 * memory being copied.
 */
void decode(json_value& dest, const char*);

json_value decode(const char*);

}

#endif
