/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __WAMPCC_JALSON_INTERNALS_H__
#define __WAMPCC_JALSON_INTERNALS_H__

// ======================================================================
//
// Internal implementation details
// -------------------------------
//
// This file should not be directly included in any files (other than jalson.h)
//
// ======================================================================



namespace internals
{

  template<typename V, typename U>
  bool is_integer(U u)
  {
    const V v_min( std::numeric_limits<V>::min());
    const V v_max( std::numeric_limits<V>::max());
    const U u_min( std::numeric_limits<U>::min());
    const U u_max( std::numeric_limits<U>::max());

    return ((long long) u_min >= (long long) v_min || u >= (U) v_min)
      && ( (unsigned long long) u_max <= (unsigned long long) v_max || u <= (U) v_max);
  }

template <typename T>
struct traits
{
};

template <>
struct traits<json_string>
{
  static const JSONType  TYPEID=eSTRING;
};

template <>
struct traits<json_object>
{
  static const JSONType  TYPEID=eOBJECT;
};

template <>
struct traits<json_array>
{
  static const JSONType  TYPEID=eARRAY;
};


class valueimpl
{
private:
  typedef enum
  {
    e_null = 0,
    e_object,
    e_array,
    e_string,
    e_bool,
    e_double,
    e_signed,
    e_unsigned,
  } JSONDetailedType;

public:


  struct Details /* POD */
  {
    JSONDetailedType type;
    union
    {
      json_array*         array;
      json_object*        object;
      json_string*        string;
      wampcc::json_uint_t uint;
      wampcc::json_int_t  sint;
      double              real;
      bool                boolean;
    } data;
  } details;

  static valueimpl::Details init_details(JSONDetailedType t = e_null);
  static void dispose_details(Details&);

public:

  valueimpl();
  valueimpl(const valueimpl&);

  /* Alter the signature of the bool constructor.  If we kept the standard bool
   * constructor, ie valueimpl(bool), then calls to valueimpl
   * constructor which passed a single template pointer, eg, valueimpl(new
   * T()), would decay to calling the bool constructor.  This is the usual C
   * rule of implicit conversion from pointer type to bool. */
  struct BoolConstructor {};
  valueimpl(bool, BoolConstructor);

  explicit valueimpl(unsigned long long );
  explicit valueimpl(long long);
  explicit valueimpl(double);

  explicit valueimpl(json_array*);
  explicit valueimpl(json_object*);
  explicit valueimpl(json_string*);

  JSONType json_type() const
  {
    switch (details.type)
    {
      case valueimpl::e_null   : return eNULL;
      case valueimpl::e_object : return eOBJECT;
      case valueimpl::e_array  : return eARRAY;
      case valueimpl::e_string : return eSTRING;
      case valueimpl::e_bool   : return eBOOL;
      case valueimpl::e_signed : return eINTEGER;
      case valueimpl::e_unsigned : return eINTEGER;
      case valueimpl::e_double : return eREAL;
      default: return eNULL;
    }
  }

  /** will free any internal pointer */
  ~valueimpl();

  valueimpl& operator=(const valueimpl& rhs);

  void swap(valueimpl&);

  bool operator==(const valueimpl& rhs) const;


private:

  const json_array&  as_type(json_array*) const   { return *details.data.array;  }
        json_array&  as_type(json_array*)         { return *details.data.array;  }
  const json_object& as_type(json_object*) const  { return *details.data.object;  }
        json_object& as_type(json_object*)        { return *details.data.object;  }
  const json_string& as_type(json_string*) const  { return *details.data.string;  }
        json_string& as_type(json_string*)        { return *details.data.string;  }

public:

  template <typename T> const T& as() const
  {
    const JSONType templtype=traits<T>::TYPEID;
    if ( templtype == this->json_type() )
      return as_type((T*) NULL);
    else
      throw type_mismatch(this->json_type(), templtype);
  }

  template <typename T> T& as()
  {
    const JSONType templtype=traits<T>::TYPEID;
    if ( templtype == this->json_type() )
      return as_type((T*) NULL);
    else
      throw type_mismatch(this->json_type(), templtype);
  }

  /* can the value be represented as a signed integer */
  bool is_sint() const;

  /* can the value be represented as an unsigned  integer */
  bool is_uint() const;

  /* return value as an integer, or throw if not possible */
  long long  as_sint_repr()  const;

  /* return value as an unsigned integer, or throw if not possible */
  unsigned long long as_uint_repr() const;

  /* return value as a double, or throw if not possible */
  double as_real() const;

  /* return boolean value, or throw if not possible */
  bool as_bool() const;

  bool as_bool_unchecked() const;

  valueimpl::Details clone_details() const;


  template<typename T>
  bool is_integer() const
  {
   if  (details.type == e_signed)
     return internals::is_integer<T>( details.data.sint );
   else if (details.type == e_unsigned)
     return internals::is_integer<T>( details.data.uint );
   else
    return false;
  }

  bool equal_int_value(const valueimpl&) const;
};

#if __cplusplus >= 201103L
static_assert( std::is_pod<valueimpl::Details>::value,
               "expected to be POD" );
#endif

}


#endif
