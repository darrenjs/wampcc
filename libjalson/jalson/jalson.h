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
integer

note there is not a separate True and False types
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

// ======================================================================
//
// Container types
//
// JSON container types are just the usual STL types.
//
// ======================================================================

class JSONValue;
typedef std::vector<JSONValue>            JSONArray;
typedef std::map<std::string, JSONValue>  JSONObject;
typedef std::string                       JSONString;

// ======================================================================
//
// Internal implementation, internals away for readability of this header.
//
#include <jalson/jalson_internals.h>
//
// ======================================================================


//  JSONValue, JSONArray,

// jalson::json_value

// value, string,

// jalson::jvalue, jalson:jarray, jstring, jalson::jobject
// jalson::json_array, json_value; json_object, json_string
// jalson::Value, Array, String , Object

/* Container for any JSON value */
class JSONValue
{
public:

  /* Constructors & assignment */

  JSONValue();  // creates null value

  JSONValue(int);
  JSONValue(long);
  JSONValue(long long);

  JSONValue(bool);
  JSONValue(double);
  JSONValue(const char*);
  JSONValue(const char*, size_t);
  JSONValue(const std::string&);
  JSONValue(const JSONArray&);
  JSONValue(const JSONObject&);

  /* WARNING: ensure the underlying implementation have uint capability before
   * using any of these. */
  JSONValue(unsigned int);
  JSONValue(unsigned long);
  JSONValue(unsigned long long);

  /* copy & assignment */

  JSONValue(const JSONValue&);
  JSONValue& operator=(const JSONValue&);

  /* equality */

  bool operator==(const JSONValue& rhs) const;
  bool operator!=(const JSONValue& rhs) const { return not this->operator==(rhs); }

  /* create various JSON types that have default value */

  static JSONValue make_null();
  static JSONValue make_array();
  static JSONValue make_object();
  static JSONValue make_string(const char* v = 0);
  static JSONValue make_bool(bool v = false);
  static JSONValue make_int(long long v = 0);
  static JSONValue make_uint(unsigned long long v = 0);
  static JSONValue make_double(double v = 0.0);

  /* type query */

  JSONType type() const { return m_impl.json_type(); }

  void check_type(JSONType t) const; // throw type_mismatch if match fails

  bool is_object()  const { return this->type() == eOBJECT; }
  bool is_array()   const { return this->type() == eARRAY; }

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


  // // and would these throw?
  // as_int16
  // as_int32
  // as_int64

  // is_int16
  // is_int32
  // is_int64

  // as_int / is_int
  // as_long / is_long
  // as_longlong / is_longlong

  // int orders = orders.as_int();

  // TODO: add methods to check the int range

  JSONString&       as_string()       { return this->as<JSONString>(); }
  const JSONString& as_string() const { return this->as<JSONString>(); }

  JSONArray&        as_array()       { return this->as<JSONArray>(); }
  const JSONArray&  as_array() const { return this->as<JSONArray>(); }

  JSONObject&       as_object()        { return this->as<JSONObject>(); }
  const JSONObject& as_object() const  { return this->as<JSONObject>(); }

  // Checked conversion to JSONArray / JSONString / JSONObject
  template<typename T> const T& as() const
  {
    ensure_type_is_json_container((T*)0);
    return m_impl.as<T>();
  }

  // Checked conversion to JSONArray / JSONString / JSONObject
  template<typename T> T& as()
  {
    ensure_type_is_json_container((T*)0);
    return m_impl.as<T>();
  }

  void swap(JSONValue&);

private:

  /* These functions exist simply to check a type specifed during a
   * template-based call is one of the JSON classes. If a type is not one of
   * these classes, it will cause a compiler error. */
  static void ensure_type_is_json_container(JSONArray*)  {}
  static void ensure_type_is_json_container(JSONString*) {}
  static void ensure_type_is_json_container(JSONObject*) {}

  internals::valueimpl  m_impl;

  friend JSONArray&  append_array  (jalson::JSONArray&);
  friend JSONObject& append_object (jalson::JSONArray&);
  friend JSONObject& insert_object (jalson::JSONObject&, const std::string&);
  friend JSONArray&  insert_array  (jalson::JSONObject&, const std::string&);
};

std::ostream& operator<<(std::ostream&, const JSONValue&);


/** Make a copy of 'src' and add to the aray */
template <typename T>
JSONValue& append(jalson::JSONArray& arr, const T& src)
{
  arr.push_back( JSONValue() );

  JSONValue& last = arr.back();
  JSONValue temp(src);
  last.swap(temp);

  return arr.back();
}


/* Append a new object or array to an array, and return the newly created
 * item */
JSONObject& append_object (JSONArray& c);
JSONArray&  append_array  (JSONArray& c);

/* Insert a new object or array to an object, and return the newly created
 * item */
JSONObject& insert_object(JSONObject&, const std::string& key);
JSONArray&  insert_array (JSONObject&, const std::string& key);

/* Utility methods for extracting a value from a container.  If not found,
 * throws json_error exceptions. */
      JSONValue& get_or_throw(      JSONObject& ob, const std::string& key);
const JSONValue& get_or_throw(const JSONObject& ob, const std::string& key);

      JSONValue& get_or_throw(      JSONArray& ob, size_t index);
const JSONValue& get_or_throw(const JSONArray& ob, size_t index);

JSONValue get(const JSONObject&, const std::string& key,
              const JSONValue & defValue = JSONValue());

JSONValue get(const JSONArray&, size_t index,
              const JSONValue & defValue = JSONValue());

/* Encode & decode functions */

/* Encode a JSON value into a JSON-text serialised representation. The JSON
 * value passed into this function should be either an Object or an Array.  This
 * is for conformance to RFC 4627. If you wish to encode other JSON types, then
 * try encode_any. */
char* encode(const JSONValue& src);

char* encode_any(const JSONValue& src);

void  decode(JSONValue& dest, const char*);

/* Wrapper to the encode function, which just presents the encoding as a
 * std::string (and so the memory does not need to be managed) */
std::string to_string(const JSONValue& src);

}

#endif
