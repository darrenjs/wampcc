/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __WAMPCC_JALSON_H__
#define __WAMPCC_JALSON_H__

#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>

#ifndef _WIN32
#  if __cplusplus < 201103L
#    error "C++11 required"
#  endif
#endif

#include <type_traits>

#include <stdint.h>

namespace wampcc
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

typedef enum {
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
  JSONType actual;    // type actual
  JSONType requested; // type requested
  type_mismatch(JSONType actual, JSONType requested);
  virtual ~type_mismatch() throw() {}
};

// exception when handling a JSON Pointer
class bad_pointer : public json_error
{
public:
  size_t path_index;
  bad_pointer(const std::string&, size_t index);
};

// exception when handling a JSON Patch
class bad_patch : public json_error
{
public:
  size_t patch_index;
  bad_patch(const std::string&, size_t index);
};

class msgpack_error : public json_error
{
public:
  size_t parsed_offset;
  size_t error_offset;
  msgpack_error(const std::string& msg, size_t parsed_offset = 0,
                size_t error_offset = 0);
  virtual ~msgpack_error() throw() {}
};

// ======================================================================
//
// Container types
//
// JSON container types are just the usual STL types.
//
// ======================================================================

class json_value;
typedef std::vector<json_value> json_array;
typedef std::map<std::string, json_value> json_object;
typedef std::string json_string;

// integer types used internally within jalson - platform widest
typedef long long json_int_t;
typedef unsigned long long json_uint_t;

// ======================================================================
//
// Internal implementation, hidden away for readability of this header.
//
#include "wampcc/json_internals.h"
//
// ======================================================================

/* Container for any JSON value */
class json_value
{
public:
  /* Constructors & assignment */

  json_value(); // creates null value

  json_value(int);
  json_value(long);
  json_value(long long);

  // caution with unsigned types, because underlying vendor may not support full
  // unsigned range
  json_value(unsigned int);
  json_value(unsigned long);
  json_value(unsigned long long);

  json_value(bool);
  json_value(double);
  json_value(const char*);
  json_value(const char*, size_t);
  json_value(const std::string&);
  json_value(const json_array&);
  json_value(const json_object&);

  /* equality */

  bool operator==(const json_value& rhs) const;
  bool operator!=(const json_value& rhs) const { return !operator==(rhs); }

  /* create various JSON types that have default value */

  static json_value make_null();
  static json_value make_array();
  static json_value make_object();
  static json_value make_string(const char* v = "");
  static json_value make_string(const char* v, size_t);
  static json_value make_string(std::string);
  static json_value make_bool(bool v = false);
  static json_value make_int(long long v = 0);
  static json_value make_uint(unsigned long long v = 0);
  static json_value make_double(double v = 0.0);

  /* type query */

  JSONType type() const { return m_impl.json_type(); }

  void check_type(JSONType t) const; // throw type_mismatch if match fails

  bool is_object() const { return type() == eOBJECT; }
  bool is_array() const { return type() == eARRAY; }
  bool is_container() const { return type() == eARRAY || type() == eOBJECT; }

  bool is_string() const { return type() == eSTRING; }
  bool is_bool() const { return type() == eBOOL; }
  bool is_true() const { return is_bool() && m_impl.as_bool_unchecked(); }
  bool is_false() const { return is_bool() && !m_impl.as_bool_unchecked(); }

  bool is_null() const { return type() == eNULL; }

  bool is_number() const { return is_real() || is_integer(); }
  bool is_real() const { return type() == eREAL; }
  bool is_integer() const { return type() == eINTEGER; }

  // int conversion can result in loss of value if actual type differs to
  // that requested
  bool is_int() const { return is_integer() && m_impl.is_sint(); }
  bool is_uint() const { return is_integer() && m_impl.is_uint(); }

  // check for specific integer ranges
  bool is_int8() const { return m_impl.is_integer<int8_t>(); }
  bool is_int16() const { return m_impl.is_integer<int16_t>(); }
  bool is_int32() const { return m_impl.is_integer<int32_t>(); }
  bool is_int64() const { return m_impl.is_integer<int64_t>(); }
  bool is_uint8() const { return m_impl.is_integer<uint8_t>(); }
  bool is_uint16() const { return m_impl.is_integer<uint16_t>(); }
  bool is_uint32() const { return m_impl.is_integer<uint32_t>(); }
  bool is_uint64() const { return m_impl.is_integer<uint64_t>(); }

  /* access the value */

  bool as_bool() const { return m_impl.as_bool(); }
  double as_real() const { return m_impl.as_real(); }

  json_int_t as_int() const { return m_impl.as_sint_repr(); }
  json_uint_t as_uint() const { return m_impl.as_uint_repr(); }

  json_string& as_string() { return this->as<json_string>(); }
  const json_string& as_string() const { return this->as<json_string>(); }

  json_array& as_array() { return this->as<json_array>(); }
  const json_array& as_array() const { return this->as<json_array>(); }

  json_object& as_object() { return this->as<json_object>(); }
  const json_object& as_object() const { return this->as<json_object>(); }

  /* utility methods if self holds json_value::array */
  json_value& operator[](size_t i) { return this->as<json_array>()[i]; }
  const json_value& operator[](size_t i) const
  {
    return this->as<json_array>()[i];
  }
  json_value& at(size_t i) { return this->as<json_array>().at(i); }
  const json_value& at(size_t i) const { return this->as<json_array>().at(i); }
  json_object& insert_object(const std::string& key);
  json_array& insert_array(const std::string& key);

  /* utility methods if self holds json_value::object */
  json_value& operator[](const std::string& k)
  {
    return this->as<json_object>()[k];
  }
  json_object& append_object();
  json_array& append_array();

  // Checked conversion to json_array / json_string / json_object
  template <typename T> const T& as() const
  {
    ensure_type_is_json_container((T*)0);
    return m_impl.as<T>();
  }

  // Checked conversion to json_array / json_string / json_object
  template <typename T> T& as()
  {
    ensure_type_is_json_container((T*)0);
    return m_impl.as<T>();
  }

  void swap(json_value&);
  void swap(json_value&&);

  /* Apply a JSON Patch (IETF RFC 6902). Can throw bad_pointer and
   * bad_patch. Returns true if patch successfully applied. */
  bool patch(const json_array&);

  /* Evaulate a JSON Pointer (IETF RFC 6902). Return a pointer to the value
   * identified by the JSON Pointer, or null if not found. If the JSON Pointer
   * has illegal syntax a bad_pointer exception is thrown.
   */
  const json_value* eval(const char* json_pointer) const;
  json_value* eval(const char* json_pointer);

// Prevent accidental initialisation of json_value from a pointer
#if __cplusplus >= 201103L
  template <typename T> json_value(const T*)
  {
    static_assert(sizeof(T) == 0,
                  "json_value cannot be initialised from pointer");
  }
#else
private:
  template <typename T> json_value(const T*){}; /* no init from pointer */
#endif

private:
  /* These functions exist simply to check a type specifed during a
   * template-based call is one of the JSON classes. If a type is not one of
   * these classes, it will cause a compiler error. */
  static void ensure_type_is_json_container(json_array*) {}
  static void ensure_type_is_json_container(json_string*) {}
  static void ensure_type_is_json_container(json_object*) {}

  internals::valueimpl m_impl;

  friend json_array& append_array(json_array&);
  friend json_object& append_object(json_array&);
  friend json_object& insert_object(json_object&, const std::string&);
  friend json_array& insert_array(json_object&, const std::string&);
};

std::ostream& operator<<(std::ostream&, const json_value&);

/** Make a copy of 'src' and add to the array, returning a reference to the
 * newly created json_value. */
template <typename T> json_value& json_append(json_array& arr, const T& src)
{
  arr.push_back(src);
  return arr.back();
}

/* Append a new object or array to an array, and return the newly created
 * item */
template <typename T> T& json_append(json_array& c)
{
  json_value new_value(T{});
  c.push_back(std::move(new_value));
  return c.back().as<T>();
}

/* Insert a new object or array to an object, and return the newly created
 * item */
template <typename T> T& json_insert(json_object& c, const std::string& key)
{
  auto ins = c.insert({key, json_value()});
  ins.first->second.swap(json_value(T{}));
  return ins.first->second.as<T>();
}

/** Return pointer to item if exists, else nullptr */
const json_value* json_get_ptr(const json_object&, const std::string& key);

/** Return pointer to item if exists, else nullptr */
json_value* json_get_ptr(json_object&, const std::string& key);

/** Return ref to item if exists, else throw field_not_found exception. */
const json_value& json_get_ref(const json_object&, const std::string& key);

/** Return ref to item if exists, else throw field_not_found exception. */
json_value& json_get_ref(json_object&, const std::string& key);

/** Return copy of item if exists, else return copy of default */
json_value json_get_copy(
    const json_object&, const std::string& key,
    const json_value& default_value_ref = json_value::make_null());

/** Return pointer to element if exists, else return default */
const json_value* json_get_ptr(const json_array&, size_t i);

/** Return pointer to element if exists, else return default */
json_value* json_get_ptr(json_array&, size_t i);

/** Return ref to element if exists, else throw field_not_found exception. */
const json_value& json_get_ref(const json_array&, size_t i);

/** Return ref to element if exists, else throw field_not_found exception. */
json_value& json_get_ref(json_array&, size_t i);

/** Return copy of element if exists, else return copy of default */
json_value json_get_copy(
    const json_array&, size_t i,
    const json_value& default_value_ref = json_value::make_null());

/* Encode & decode functions */

/* Encode a JSON value into a JSON-text serialised representation. The JSON
 * value passed into this function should be either an Object or an Array.  This
 * is for conformance to RFC 4627. If you wish to encode other JSON types, then
 * try encode_any. */
std::string json_encode(const json_value& src);
std::string json_encode_any(const json_value& src);

/* Decode into 'dest' out parameters, which on legacy C++ reduces the amount of
 * memory being copied.
 */
void json_decode(json_value& dest, const char*, size_t);
void json_decode(json_value& dest, const char*);

json_value json_decode(const char*, size_t);
json_value json_decode(const char*);

// implementation of inline methods
inline json_array& json_value::append_array()
{
  return json_append<json_array>(this->as<json_array>());
}

inline json_object& json_value::append_object()
{
  return json_append<json_object>(this->as<json_array>());
}

inline json_object& json_value::insert_object(const std::string& key)
{
  return json_insert<json_object>(this->as<json_object>(), key);
}

inline json_array& json_value::insert_array(const std::string& key)
{
  return json_insert<json_array>(this->as<json_object>(), key);
}

/* Decode a msgpack byte stream */
json_value json_msgpack_decode(const char*, size_t);

/* Encode to msgpack.  Returned memory region is managed by unique_ptr. */
typedef std::pair<char*, size_t> region;
std::unique_ptr<region, void (*)(region*)> json_msgpack_encode(
    const json_value& src);

} // namespace

#endif
