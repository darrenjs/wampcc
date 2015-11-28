#ifndef __JALSON_INTERNALS_H__
#define __JALSON_INTERNALS_H__

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

template <typename T>
struct traits
{
};

template <>
struct traits<JSONString>
{
  static const JSONType  TYPEID=eSTRING;
};

template <>
struct traits<JSONObject>
{
  static const JSONType  TYPEID=eOBJECT;
};

template <>
struct traits<JSONArray>
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
      // TODO: replace thse 64t?
      JSONArray*         array;
      JSONObject*        object;
      JSONString*        string;
      unsigned long long uint;
      long long          sint;
      double             real;
      bool               boolean;
    } data;
  } details;

  static valueimpl::Details init_details(JSONDetailedType t = e_null);
  static void dispose_details(Details&);

public:

  // TODO: need to recall what was problem with int/void* explicit
  // constructor

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

  explicit valueimpl(JSONArray*);
  explicit valueimpl(JSONObject*);
  explicit valueimpl(JSONString*);

  // TODO: move to the impl code
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

  const JSONArray&  as_type(JSONArray*) const   { return *details.data.array;  }
        JSONArray&  as_type(JSONArray*)         { return *details.data.array;  }
  const JSONObject& as_type(JSONObject*) const  { return *details.data.object;  }
        JSONObject& as_type(JSONObject*)        { return *details.data.object;  }
  const JSONString& as_type(JSONString*) const  { return *details.data.string;  }
        JSONString& as_type(JSONString*)        { return *details.data.string;  }

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

  /* can the value be represented as a integer */
  bool is_sint()  const
  {
    if  (details.type == e_signed) return true;

    // TODO: review
    if ((details.type == e_unsigned)
        and
        (details.data.uint <= 9223372036854775807LL)) return true;

    return false;
  }

  bool is_uint() const
  {
    if  (details.type == e_unsigned) return true;

    if ((details.type == e_signed)
        and
        (details.data.sint >= 0)) return true;

    return false;
  }

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
};

}


#endif
