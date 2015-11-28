#include <jalson/jalson.h>

#include <iostream>
#include <sstream>

#include <string.h>



namespace jalson {

const char* type_to_str(JSONType t)
{
  switch(t)
  {
    case jalson::eOBJECT  : return "object";
    case jalson::eARRAY   : return "array";
    case jalson::eSTRING  : return "string";
    case jalson::eREAL    : return "real";
    case jalson::eINTEGER : return "integer";
    case jalson::eBOOL    : return "bool";
    case jalson::eNULL    : return "null";
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

valueimpl::valueimpl(JSONArray* a)
  : details( init_details(valueimpl::e_array) )
{
  details.data.array = a;
}

valueimpl::valueimpl(JSONObject* a)
  : details( init_details(valueimpl::e_object) )
{
  details.data.object = a;
}


valueimpl::valueimpl(JSONString* a)
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
      retval.data.object = new JSONObject(*details.data.object);
      break;
    }
    case valueimpl::e_array:
    {
      retval.data.array = new JSONArray(*details.data.array);
      break;
    }
    case valueimpl::e_string:
    {
      retval.data.string = new JSONString(*details.data.string);
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
      default: return true; // does types: true, false, null,int, double
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


// poor mans template
#define ARRAY_APPEND( C, T )                         \
  T * newitem = new T ();                            \
  internals::valueimpl temp( newitem );              \
  C.push_back( JSONValue() );                        \
  C.back().m_impl.swap( temp );                      \
  return *newitem;

JSONArray  &  append_array(jalson::JSONArray& c)
{
  ARRAY_APPEND(c, JSONArray);
}

JSONObject  &  append_object(jalson::JSONArray& c)
{
  ARRAY_APPEND(c, JSONObject);
}


// poor mans template
#define ARRAY_APPEND( C, T )                         \
  T * newitem = new T ();                            \
  internals::valueimpl temp( newitem );              \
  C.push_back( JSONValue() );                        \
  C.back().m_impl.swap( temp );                      \
  return *newitem;



JSONObject& insert_object(jalson::JSONObject& c, const std::string& key)
{
//  c[ key ] = JSONValue::make_object();
//  return c[key].as_object();

  JSONObject * newitem = new JSONObject();
  internals::valueimpl temp( newitem );

  std::pair< jalson::JSONObject::iterator, bool> ins =
    c.insert(std::make_pair(key, JSONValue()));

  ins.first->second.m_impl.swap( temp );
  return *newitem;
}



JSONArray& insert_array(jalson::JSONObject& c, const std::string& key)
{
  JSONArray * newitem = new JSONArray();
  internals::valueimpl temp( newitem );

  std::pair< jalson::JSONObject::iterator, bool> ins =
    c.insert(std::make_pair(key, JSONValue()));

  ins.first->second.m_impl.swap( temp );
  return *newitem;
}




JSONValue& get_or_throw(JSONObject & ob, const std::string& key)
{
  JSONObject::iterator it = ob.find( key );
  if (it != ob.end())
  {
    return it->second;
  }
  else throw field_not_found(key);
}

const JSONValue& get_or_throw(const JSONObject& ob, const std::string& key)
{
  JSONObject::const_iterator it = ob.find( key );
  if (it != ob.end())
  {
    return it->second;
  }
  else throw field_not_found(key);
}

JSONValue& get_or_throw(JSONArray& ob, size_t i)
{
  if (i >= ob.size()) throw out_of_range(i);
  return ob[i];
}

const JSONValue& get_or_throw(const JSONArray& ob, size_t i)
{
  if (i >= ob.size()) throw out_of_range(i);
  return ob[i];
}


JSONValue get(const JSONObject& c, const std::string& key,
              const JSONValue & defaultValue)
{
  JSONObject::const_iterator it = c.find( key );
  if (it != c.end())
  {
    return it->second;
  }
  else
    return defaultValue;
}


JSONValue get(const JSONArray& c, size_t index,
              const JSONValue & defaultValue)
{
  if (index < c.size())
    return c[index];
  else
    return defaultValue;
}

//----------------------------------------------------------------------

JSONValue::JSONValue()
  : m_impl()
{
}

JSONValue::JSONValue(const std::string& s)
  : m_impl(new JSONString(s))
{
}

JSONValue::JSONValue(const char* s)
  : m_impl(s? new JSONString(s) : new JSONString())
{
}

JSONValue::JSONValue(const char* s, size_t  n)
  : m_impl(s? new JSONString(s, n) : new JSONString())
{
}

JSONValue::JSONValue(const JSONValue& rhs)
  : m_impl( rhs.m_impl )
{
}

JSONValue::JSONValue(const JSONArray& rhs)
  : m_impl(new JSONArray(rhs))
{
}

JSONValue::JSONValue(const JSONObject& rhs)
  : m_impl( new JSONObject(rhs) )
{
}


JSONValue::JSONValue(bool b)
  : m_impl( b, internals::valueimpl::BoolConstructor())
{
}

JSONValue::JSONValue(int i)
  : m_impl((long long)i)
{
}

JSONValue::JSONValue(long i)
  : m_impl((long long)i)
{
}

JSONValue::JSONValue(long long i)
  : m_impl((long long)i)
{
}

JSONValue::JSONValue(double i)
  : m_impl( i )
{
}

JSONValue::JSONValue(unsigned int i)
  : m_impl((unsigned long long)i)
{
}

JSONValue::JSONValue(unsigned long i)
  : m_impl((unsigned long long)i)
{
}

JSONValue::JSONValue(unsigned long long i)
  : m_impl(i)
{
}

void JSONValue::swap(JSONValue& other)
{
  this->m_impl.swap(other.m_impl);
}

JSONValue JSONValue::make_null()
{
  return JSONValue();
}

JSONValue JSONValue::make_array()
{
  internals::valueimpl vimpl( new JSONArray() );

  JSONValue v;
  v.m_impl.swap( vimpl );

  return v;
}

JSONValue JSONValue::make_object()
{
  internals::valueimpl vimpl( new JSONObject() );

  JSONValue v;
  v.m_impl.swap( vimpl );

  return v;
}

JSONValue JSONValue::make_string(const char* s)
{
  JSONValue retval = std::string(s) ;
  return retval;
}

JSONValue JSONValue::make_bool(bool v)
{
  return JSONValue(v);
}

JSONValue JSONValue::make_int(long long v)
{
  JSONValue retval(v);
  return retval;
}

JSONValue JSONValue::make_uint(unsigned long long v)
{
  JSONValue retval(v);
  return retval;
}

JSONValue JSONValue::make_double(double v)
{
  JSONValue retval(v);
  return retval;
}


JSONValue& JSONValue::operator=(const JSONValue& src)
{
  m_impl = src.m_impl;
  return *this;
}


bool JSONValue::operator==(const JSONValue& rhs) const
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

//----------------------------------------------------------------------


void JSONValue::check_type(JSONType t) const
{
  if (this->type() != t)
    throw type_mismatch(this->type(), t);
}




std::ostream& operator<<(std::ostream& os, const JSONValue& v)
{
  if (v.is_object() || v.is_array())
  {
    char* enc = JSONEncode(v);
    os << enc;
    delete [] enc;
  }
  else
  {
    char* enc = JSONEncodeAny(v);
    os << enc;
    delete [] enc;
  }

  return os;
}


} // namespace jalson



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
