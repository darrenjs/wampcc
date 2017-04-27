#include "wampcc/json.h"
#include "msgpack.h"
#include "json_pointer.h"

#include <iostream>
#include <sstream>
#include <limits>

#include <string.h>

namespace wampcc {

namespace internals {


  bool valueimpl::is_sint()  const
  {
    if  (details.type == e_signed) return true;

    if ((details.type == e_unsigned)   // 0----------SMAX--------UMAX
        and
        (details.data.uint <= (json_uint_t)std::numeric_limits<json_int_t>::max() )) return true;

    return false;
  }

  bool valueimpl::is_uint() const
  {
    if  (details.type == e_unsigned) return true;

    if ((details.type == e_signed)
        and
        (details.data.sint >= 0)) return true;

    return false;
  }


}


const char* type_to_str(JSONType t)
{
  switch(t)
  {
    case wampcc::eOBJECT  : return "object";
    case wampcc::eARRAY   : return "array";
    case wampcc::eSTRING  : return "string";
    case wampcc::eREAL    : return "real";
    case wampcc::eINTEGER : return "integer";
    case wampcc::eBOOL    : return "bool";
    case wampcc::eNULL    : return "null";
    default            : return "invalid";
  }
}





namespace internals {


valueimpl::Details valueimpl::init_details(JSONDetailedType t)
{
  // create variable ... assume its in an undefined state
  valueimpl::Details d;

  // make best effort to initialise everything
  memset(&d, 0, sizeof(d));
  d.type = t;

  return d;
}


void valueimpl::dispose_details(valueimpl::Details& d)
{
  switch(d.type)
  {
    case e_object :
    {
      delete d.data.object;
      break;
    }
    case e_array:
    {
      delete d.data.array;
      break;
    }
    case e_string :
    {
      delete d.data.string;
      break;
    }
    default: break;
  }
  d = init_details();
}


valueimpl::valueimpl()
  : details( init_details() )
{
}


valueimpl::valueimpl(const valueimpl& rhs)
  : details( rhs.clone_details() )
{
}


valueimpl::valueimpl(bool b, BoolConstructor)
  : details( init_details( valueimpl::e_bool ))
{
  details.data.boolean = b;
}

valueimpl::valueimpl(unsigned long long n)
  : details( init_details(valueimpl::e_unsigned) )
{
  details.data.uint = n;
}

valueimpl::valueimpl(long long n)
  : details( init_details(valueimpl::e_signed) )
{
  details.data.sint = n;
}

valueimpl::valueimpl(double n)
  : details( init_details(valueimpl::e_double) )
{
  details.data.real = n;
}

valueimpl::valueimpl(json_array* a)
  : details( init_details(valueimpl::e_array) )
{
  details.data.array = a;
}

valueimpl::valueimpl(json_object* a)
  : details( init_details(valueimpl::e_object) )
{
  details.data.object = a;
}


valueimpl::valueimpl(json_string* a)
  : details( init_details(valueimpl::e_string) )
{
  details.data.string = a;
}


valueimpl& valueimpl::operator=(const valueimpl& rhs)
{
  Details copy = rhs.clone_details();

  // delete our own data
  dispose_details(this->details);

  this->details = copy;  // bitwise

  return *this;
}

valueimpl::~valueimpl()
{
  dispose_details(this->details);
}

void valueimpl::swap(valueimpl& other)
{
  Details tmp   = other.details;
  other.details = this->details;
  this->details = tmp;
}

valueimpl::Details valueimpl::clone_details() const
{
  // basic bitwise copy is sufficent for value-types
  valueimpl::Details retval = this->details;

  // ... now handle pointer types
  switch(this->details.type)
  {
    case valueimpl::e_object :
    {
      retval.data.object = new json_object(*details.data.object);
      break;
    }
    case valueimpl::e_array:
    {
      retval.data.array = new json_array(*details.data.array);
      break;
    }
    case valueimpl::e_string:
    {
      retval.data.string = new json_string(*details.data.string);
      break;
    }
    default: break;
  }
  return retval;
}

bool valueimpl::operator==(const valueimpl& rhs) const
{
  if (this->details.type == rhs.details.type)
  {
    switch(this->details.type)
    {
      case valueimpl::e_null:
      {
        return true;
      }
      case valueimpl::e_object:
      {
        return *(this->details.data.object) == *(rhs.details.data.object);
      }
      case valueimpl::e_array:
      {
        return *this->details.data.array == *rhs.details.data.array;
      }
      case valueimpl::e_string:
      {
        return *(this->details.data.string) ==  *rhs.details.data.string;
      }
      case valueimpl::e_bool:
      {
        return this->details.data.boolean == rhs.details.data.boolean;
      }
      case valueimpl::e_double:
      {
        return this->details.data.real == rhs.details.data.real;
      }
      case valueimpl::e_signed:
      {
        return this->details.data.sint == rhs.details.data.sint;
      }
      case valueimpl::e_unsigned:
      {
        return this->details.data.uint == rhs.details.data.uint;
      }
      default: return false;
    }
  }
  else return false;
}

long long valueimpl::as_sint_repr()  const
{
  if (details.type == e_signed)
  {
    return details.data.sint;
  }
  else if (details.type == e_unsigned)
  {
    return  (long long) details.data.uint;  // can be loss of precision
  }
  else
  {
    throw type_mismatch(this->json_type(), eINTEGER);
  }
}

unsigned long long valueimpl::as_uint_repr()  const
{
  if (details.type == e_signed)
  {
    return (unsigned long long) details.data.sint; // can be loss of precision
  }
  else if (details.type == e_unsigned)
  {
    return details.data.uint;
  }
  else
  {
    throw type_mismatch(this->json_type(), eINTEGER);
  }
}

/* return value as an unsigned integer, or throw if not possible */
double valueimpl::as_real() const
{
  if ( valueimpl::e_double == details.type )
    return details.data.real;
  else
    throw type_mismatch(this->json_type(), eREAL);
}

bool valueimpl::as_bool() const
{
  if ( valueimpl::e_bool == details.type )
    return as_bool_unchecked();
  else
    throw type_mismatch(this->json_type(), eBOOL);
}

bool valueimpl::as_bool_unchecked() const
{
  /* caller takes responsibilty for ensuring 'details' holds a boolean */
  return details.data.boolean;
}


} // namespace

//----------------------------------------------------------------------

json_value::json_value()
  : m_impl()
{
}

json_value::json_value(const std::string& s)
  : m_impl(new json_string(s))
{
}

json_value::json_value(const char* s)
  : m_impl(s? new json_string(s) : new json_string())
{
}

json_value::json_value(const char* s, size_t  n)
  : m_impl(s? new json_string(s, n) : new json_string())
{
}

json_value::json_value(const json_value& rhs)
  : m_impl( rhs.m_impl )
{
}

json_value::json_value(const json_array& rhs)
  : m_impl(new json_array(rhs))
{
}

json_value::json_value(const json_object& rhs)
  : m_impl( new json_object(rhs) )
{
}


json_value::json_value(bool b)
  : m_impl( b, internals::valueimpl::BoolConstructor())
{
}

json_value::json_value(int i)
  : m_impl((long long)i)
{
}

json_value::json_value(long i)
  : m_impl((long long)i)
{
}

json_value::json_value(long long i)
  : m_impl((long long)i)
{
}

json_value::json_value(double i)
  : m_impl( i )
{
}

json_value::json_value(unsigned int i)
  : m_impl((unsigned long long)i)
{
}

json_value::json_value(unsigned long i)
  : m_impl((unsigned long long)i)
{
}

json_value::json_value(unsigned long long i)
  : m_impl(i)
{
}

void json_value::swap(json_value& other)
{
  this->m_impl.swap(other.m_impl);
}

void json_value::swap(json_value&& other)
{
  this->m_impl.swap(other.m_impl);
}

json_value json_value::make_null()
{
  return json_value();
}

json_value json_value::make_array()
{
  internals::valueimpl vimpl( new json_array() );

  json_value v;
  v.m_impl.swap( vimpl );

  return v;
}

json_value json_value::make_object()
{
  internals::valueimpl vimpl( new json_object() );

  json_value v;
  v.m_impl.swap( vimpl );

  return v;
}

json_value json_value::make_string(const char* s)
{
  json_value retval = std::string(s) ;
  return retval;
}

json_value json_value::make_string(const char* s, size_t l)
{
  json_value retval = std::string(s, l) ;
  return retval;
}

json_value json_value::make_string(std::string s)
{
  json_value retval = std::move(s);
  return retval;
}

json_value json_value::make_bool(bool v)
{
  return json_value(v);
}

json_value json_value::make_int(long long v)
{
  json_value retval(v);
  return retval;
}

json_value json_value::make_uint(unsigned long long v)
{
  json_value retval(v);
  return retval;
}

json_value json_value::make_double(double v)
{
  json_value retval(v);
  return retval;
}


json_value& json_value::operator=(const json_value& src)
{
  m_impl = src.m_impl;
  return *this;
}


bool json_value::operator==(const json_value& rhs) const
{
  if (this->type() != rhs.type())
    return false;
  else
    return this->m_impl == rhs.m_impl;
}

//----------------------------------------------------------------------

json_error::json_error(const std::string& msg)
  : std::runtime_error(msg)
{
}


static std::string out_of_range_str(size_t __requested)
{
  std::ostringstream os;
  os << "array lookup out of range for index " << __requested;
  return os.str();
}


out_of_range::out_of_range(size_t __requested)
  : json_error( out_of_range_str( __requested )),
    requested(__requested)
{
}


parse_error::parse_error(const std::string& msg)
  : json_error( msg ),
    line(0),
    column(0),
    position(0)
{
}


static std::string field_not_found_str(const std::string& s)
{
  std::ostringstream os;
  os << "field not found '"<< s << "'";
  return os.str();
}


field_not_found::field_not_found(const std::string& s)
  :  json_error(  field_not_found_str(s) ),
     field(s)
{
}


static std::string type_mismatch_str(JSONType __actual,
                                     JSONType __requested)
{
  std::ostringstream os;
  os << "type mismatch: actual='" << type_to_str(__actual)
     << "' requested='"<< type_to_str(__requested) <<"'";
  return os.str();
}


type_mismatch::type_mismatch(JSONType __actual,
                             JSONType __requested)
  : json_error(type_mismatch_str(__actual, __requested)),
    actual(__actual),
    requested(__requested)
{
}


bad_pointer::bad_pointer(const std::string& msg, size_t __index_failed)
  : json_error(msg),
    path_index( __index_failed )
{
}


bad_patch::bad_patch(const std::string& msg,
                     size_t i)
  : json_error(msg),
      patch_index(i)
{
}


//----------------------------------------------------------------------


void json_value::check_type(JSONType t) const
{
  if (this->type() != t)
    throw type_mismatch(this->type(), t);
}




std::ostream& operator<<(std::ostream& os, const json_value& v)
{
  if (v.is_object() || v.is_array())
  {
    os << json_encode(v);
  }
  else
  {
    os << json_encode_any(v);
  }

  return os;
}


void json_value::patch(const json_array& patch)
{
  apply_patch(*this, patch);
}

const json_value * json_value::eval(const char* path) const
{
  return eval_json_pointer(*this, path);
}

json_value * json_value::eval(const char* path)
{
  return eval_json_pointer(*this, path);
}

const json_value* json_get_ptr(const json_object& ob, const std::string& key)
{
  json_object::const_iterator it = ob.find( key );
  if (it != ob.end())
    return &it->second;
  else
    return nullptr;
}

json_value* json_get_ptr(json_object& ob, const std::string& key)
{
  json_object::iterator it = ob.find( key );
  if (it != ob.end())
    return &it->second;
  else
    return nullptr;
}


const json_value& json_get_ref(const json_object& ob, const std::string& key)
{
  json_object::const_iterator it = ob.find( key );

  if (it != ob.end())
    return it->second;
  else
    throw field_not_found(key);
}

json_value& json_get_ref(json_object& ob, const std::string& key)
{
  json_object::iterator it = ob.find( key );

  if (it != ob.end())
    return it->second;
  else
    throw field_not_found(key);
}

json_value json_get_copy(const json_object& ob, const std::string& key,
                    const json_value& defval)
{
  json_object::const_iterator it = ob.find( key );

  if (it != ob.end())
    return it->second;
  else
    return defval;
}

const json_value* json_get_ptr(const json_array& ar, size_t i)
{
  return (i < ar.size())? &ar[i] : nullptr;
}

json_value* json_get_ptr(json_array& ar, size_t i)
{
  return (i < ar.size())? &ar[i] : nullptr;
}

const json_value& json_get_ref(const json_array& ar, size_t i)
{
  if (i < ar.size())
    return ar[i];
  else
    throw out_of_range(i);
}

json_value& json_get_ref(json_array& ar, size_t i)
{
  if (i < ar.size())
    return ar[i];
  else
    throw out_of_range(i);
}

json_value json_get_copy(const json_array& ar, size_t i,
                    const json_value & default_value_ref)
{
  return i < ar.size()? ar[i] : default_value_ref;
}


void json_msgpack_decode(json_value& dest, const char*, size_t)
{

}

std::unique_ptr<region, void(*)(region*)> json_msgpack_encode(const json_array& src)
{
  msgpack_encoder encoder;

  return encoder.encode(src);
}



} // namespace wampcc



// http://stackoverflow.com/questions/17224256/function-checking-if-an-integer-type-can-fit-a-value-of-possibly-different-inte

// #include <limits>
// #include <stdint.h>

// using std::numeric_limits;

// template <typename T, typename U>
//     bool CanTypeFitValue(const U value) {
//         const intmax_t botT = intmax_t(numeric_limits<T>::min() );
//         const intmax_t botU = intmax_t(numeric_limits<U>::min() );
//         const uintmax_t topT = uintmax_t(numeric_limits<T>::max() );
//         const uintmax_t topU = uintmax_t(numeric_limits<U>::max() );
//         return !( (botT > botU && value < static_cast<U> (botT)) || (topT < topU && value > static_cast<U> (topT)) );
//     }
