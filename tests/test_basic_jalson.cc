#include "jalson/jalson.h"
#include <iostream>
#include <stdexcept>
#include <list>


#include "testcase.h"

class MyType
{
};

//----------------------------------------------------------------------
DEFTEST(  basic_json_object )
{
  jalson::json_value temp(1);
  return 1;
}


//----------------------------------------------------------------------
DEFTEST( jsonarray_basic_append )
{
  // test array addition, and functions which append
  jalson::json_array msg;

  msg.push_back( 0 );
  msg.push_back( 1 );
  msg.push_back("string");
  msg.push_back( true );

  jalson::json_append<jalson::json_array>(msg).push_back("a");
  jalson::json_append<jalson::json_object>(msg)["b"] = "c";

  std::string enc  = jalson::json_encode(msg) ;
  std::cout << enc << "\n";
  return  ( enc == "[0, 1, \"string\", true, [\"a\"], {\"b\": \"c\"}]");
}

//----------------------------------------------------------------------
DEFTEST( convert_type_to_string )
{
  jalson::json_value any1("should be string");
  jalson::json_string str1 = any1.as_string();
  jalson::json_value any2 = any1;
  jalson::json_string str2 = any1.as_string();

  jalson::json_value any3;
  any3.swap(any1);
  jalson::json_string str3 = any3.as_string();

  return (str1 == str1) and (str1 == str3);
}

//----------------------------------------------------------------------
DEFTEST( size_of )
{
  //std::cout << "sizeof(JSONNumber) : " << sizeof(jalson::JSONNumber) << "\n";
  std::cout << "sizeof(json_array) : " << sizeof(jalson::json_array) << "\n";
  std::cout << "sizeof(value) : " << sizeof(jalson::internals::valueimpl) << "\n";
  return 1;
}


//----------------------------------------------------------------------
DEFTEST( misc_operations )
{
  jalson::json_array ar1;

  jalson::json_append(ar1, 100);
  jalson::json_append(ar1, "mystring");

  jalson::json_value acopy = jalson::json_value( ar1 );
  jalson::json_array ar2 = acopy.as<jalson::json_array>();


  //MyType ar3 = acopy.as< MyType >();

  jalson::json_value i1 = ar2[1];
  jalson::json_string s1 = i1.as<jalson::json_string>();

  return (s1 == "mystring");
}

//----------------------------------------------------------------------

DEFTEST( encoding_call_message )
{
  const std::string foreign_sid = "a1";
  const std::string foreign_rpc = "myrpc";
  int reqid = 100;

  jalson::json_array msg;
  jalson::json_append(msg, "call");
  jalson::json_append<jalson::json_object>(msg);
  jalson::json_append(msg, foreign_sid + ":" +foreign_rpc);
  jalson::json_append(msg, reqid);
  jalson::json_append<jalson::json_object>(msg);

  msg.push_back( 50.25 );

  jalson::json_value any = msg;
  std::string encoding = jalson::json_encode( any );
  //std::cout << "encoding: " << encoding << "\n";

  return encoding=="[\"call\", {}, \"a1:myrpc\", 100, {}, 50.25]";
}

jalson::json_value takecopy(const jalson::json_value& src)
{
  jalson::json_value temp(0);
  temp = src;
  return temp;
}

//----------------------------------------------------------------------
DEFTEST( support_for_various_int_types )
{
  jalson::json_array msg;

  int   _int = 1;
  short _short = 2;
  long  _long = 3;
  long long  int _longlong  = 5;
  unsigned int _uint = 6;
  unsigned int _ulong = 7;

  msg.push_back(0);
  msg.push_back(_int);
  msg.push_back(_short);
  msg.push_back(_long);
  msg.push_back(_longlong);   // <---- doesn't compile

  msg.push_back(_uint);   // <---- doesn't compile, unless this type is also a
  msg.push_back(_ulong);   // <---- doesn't compile, unless this type is also a
                          // constructor

  msg.push_back(0);
  msg.push_back("x");


  jalson::json_value any = takecopy(msg); // test a copy too
  std::string encoding = jalson::json_encode( any );
  std::cout << "encoding: " << encoding << "\n";

  return encoding=="[0, 1, 2, 3, 5, 6, 7, 0, \"x\"]";
}

//----------------------------------------------------------------------
DEFTEST( test_operator_eq )
{
  jalson::json_array msg(10);

  // int   _int            = 1;
  // short _short          = 2;
  // long  _long           = 3;
  // long long  _longlong  = 4;


  msg[0] = 0;
  msg[1] = 2.5;
  msg[2] = true;
  msg[3] = false;
  msg[4] = "hello";
  // msg[5] = (long)-1;
  // msg[ msg.size()-1 ] = "last";

//   msg.append(_int);
//   msg.append(_short);
//   msg.append(_long);
//   msg.append(_longlong);
//   msg[1] = 10;

  ASSERT_TRUE( msg[0].is_number() );
  ASSERT_TRUE( msg[2].is_bool() );
  ASSERT_TRUE( msg[2].is_true() );
  ASSERT_TRUE( msg[3].is_bool() );
  ASSERT_TRUE( msg[3].is_false() );
  ASSERT_TRUE( msg[4].is_string() );

  jalson::json_value any = msg;
  std::string encoding = jalson::json_encode( any );
  std::cout << "encoding: " << encoding << "\n";

//  check( );

//   return encoding=="[0, 10, 2, 3, 4]";
  return true;
}


DEFTEST( map_examples )
{
  jalson::json_value a = jalson::json_value::make_array();

  a.as<jalson::json_array>().push_back(jalson::json_value::make_object());
  jalson::json_append<jalson::json_array>( a.as<jalson::json_array>() );
  auto & obj = jalson::json_append<jalson::json_object>( a.as<jalson::json_array>() );

  obj["a"]=0;
  obj["b"]=1;
  obj["c"]=-1;
  obj["d"]="hello";
  obj["e"]= jalson::json_value::make_object();
  jalson::json_object& obj2 = jalson::json_insert<jalson::json_object>(obj, "X");
  /*jalson::json_array& arr2  =*/ jalson::json_insert<jalson::json_array>(obj2, "X");
  std::string encoding = jalson::json_encode( a );
  std::cout << "encoding: " << encoding << "\n";

  return 1;
}

DEFTEST ( encoding_example_1 )
{
  const char* src="[\"SUBSCRIBE\", 0, {}, \"T1\"]";
  jalson::json_value a;
  jalson::json_decode(a, src);

  jalson::json_array msg=a.as<jalson::json_array>();
  jalson::json_value        reqid = msg.at(1);
  jalson::json_object       opt = msg.at(2).as<jalson::json_object>();
  jalson::json_string topicname = msg.at(3).as<jalson::json_string>();

  return true;
}


DEFTEST( int_and_uint_and_real )
{
  const char* src="[0, -1, 1, 1.25, \"x\" ]";
  jalson::json_value a;
  jalson::json_decode(a, src);

  jalson::json_array& msg=a.as<jalson::json_array>();

  ASSERT_TRUE( msg[0].is_uint() );
  ASSERT_TRUE( msg[0].is_int() );
  ASSERT_TRUE( msg[1].is_int() );
  ASSERT_EQ  ( msg[1].is_uint(),false );
  ASSERT_TRUE( msg[2].is_int() );
  ASSERT_TRUE( msg[2].is_uint() );
  ASSERT_TRUE( msg[3].is_number() );
  ASSERT_TRUE( msg[3].is_real() );
  ASSERT_TRUE( msg[3].as_real() ==  1.25 );
  ASSERT_TRUE( !msg[4].is_number() );
  ASSERT_TRUE( msg[4].is_string() );
  ASSERT_TRUE( !msg[4].is_object() );
  ASSERT_TRUE( !msg[4].is_array() );

  return true;
}


DEFTEST( compiler_check )
{
  /* here we are just checking that various expressions involving construction
   * and assignment which use primitive integer types, actually compile */
  {
    jalson::json_value value;
    value = 0;
    value = 1;
    value = "0";
    value = jalson::json_value::make_null();
    value = jalson::json_string();
    value = jalson::json_array();
    value = jalson::json_object();
  }
  {
    char v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    short v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    signed char v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    signed short v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    unsigned char v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    unsigned short v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    int v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    int v = 0;
    jalson::json_value value( v );
    value = v;
    value = jalson::json_value::make_int(v);
  }
  {
    long v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    long long v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    bool v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    const char* v = 0;
    jalson::json_value value( v );
    value = v;
  }
  // {
  //   float * v = 0;
  //   jalson::json_value value( v ); // error!
  //   value = v;
  // }
  // {
  //   double * v = 0;
  //   jalson::json_value value( v ); // error!
  //   value = v;
  // }
  {
    std::string  v("test");
    jalson::json_value value( v );
    value = v;
  }
  {
    const char*  v = "test";
    jalson::json_value value( v );
    value = v;
  }

  return true;
}

//----------------------------------------------------------------------
DEFTEST( copy_memleak )
{

  jalson::json_value jv;

  jalson::json_array ja;
  ja.push_back( "hello" );
  ja.push_back( "world" );   //TODO: why do I not see thi value arrise at the other side? Jalson error?

  jv = ja ;
  jalson::json_value jv2 = jv;

  std::cout << "encoding: " << jalson::json_encode_any( jv2 ) << "\n";

  return 1;
}

//----------------------------------------------------------------------
DEFTEST( equality )
{
  jalson::json_value j1 = jalson::json_decode( "{ \"foo\": [50, 20, 30, 40]} " );
  jalson::json_value j2 = jalson::json_decode( "{ \"foo\": [10, 20, 30, 40]} " );
  jalson::json_value j3 = jalson::json_decode( "{ \"foo\": [10, 20, 30, 40]} " );

  ASSERT_TRUE( j1 == j1 );
  ASSERT_TRUE( (j1 != j1) == false );
  ASSERT_TRUE( j1 != j2 );
  ASSERT_TRUE( (j1 == j2) == false );
  ASSERT_TRUE( j2 == j3 );
  ASSERT_TRUE( (j2 != j3) == false );


  jalson::json_value j4 = jalson::json_decode( "{ \"foo\": [1.1, 2.2 ], \"a\": true }" );
  jalson::json_value j5 = jalson::json_decode( "{ \"foo\": [1.2, 2.3 ], \"a\": true }" );
  jalson::json_value j6 = jalson::json_decode( "{ \"a\":true, \"foo\": [1.1, 2.2 ] }" );

  ASSERT_TRUE( j4 == j4 );
  ASSERT_TRUE( j4 != j5 );
  ASSERT_TRUE( (j4 == j5) == false );
  ASSERT_TRUE( j4 == j6 );

  jalson::json_value j7 = jalson::json_decode( "{ \"foo\": [-50, -20, -30, -40]} " );
  jalson::json_value j8 = jalson::json_decode( "{ \"foo\": [-10, -20, -30, -40]} " );
  jalson::json_value j9 = jalson::json_decode( "{ \"foo\": [-10, -20, -30, -40]} " );

  ASSERT_TRUE( j7 == j7 );
  ASSERT_TRUE( (j7 != j7) == false );
  ASSERT_TRUE( j7 != j8 );
  ASSERT_TRUE( (j7 == j8) == false );
  ASSERT_TRUE( j8 == j9 );
  ASSERT_TRUE( (j8 != j9) == false );

  jalson::json_value j10 = jalson::json_decode( "{ \"foo\": [true, false, true, false ]} " );
  jalson::json_value j11 = jalson::json_decode( "{ \"foo\": [true, false, true, true  ]} " );
  jalson::json_value j12 = jalson::json_decode( "{ \"foo\": [true, false, true, true  ]} " );

  ASSERT_TRUE( j10 == j10 );
  ASSERT_TRUE( (j10 != j10) == false );
  ASSERT_TRUE( j10 != j11 );
  ASSERT_TRUE( (j10 == j11) == false );
  ASSERT_TRUE( j11 == j12 );
  ASSERT_TRUE( (j11 != j12) == false );


  return 1;
}

//----------------------------------------------------------------------
DEFTEST( getters_api )
{
  const jalson::json_value j1 = jalson::json_decode( "{ \"foo\": [50, 20, 30, 40]} " );

  const jalson::json_object msg;


  const jalson::json_value * id  = jalson::json_get_ptr(msg, "id");
  ASSERT_TRUE( id == NULL);
  // const jalson::json_value & id2 = jalson::get_ref(msg, "id");

  const jalson::json_value & id4 = jalson::json_get_copy(msg, "id", jalson::json_value::make_string("hello"));
  ASSERT_TRUE( id4 == jalson::json_value::make_string("hello") );

  bool id5_exception_thrown=false;
  try
  {
    jalson::json_get_ref(msg, "id");
  }
  catch (jalson::field_not_found& e)
  {
    id5_exception_thrown = true;
  }
  ASSERT_TRUE(id5_exception_thrown);

  const jalson::json_value expected = jalson::json_value::make_string("xyz");
  std::string challmsg = jalson::json_get_copy(msg, "challenge", "xyz").as_string();
  std::cout << "challmsg: >" << challmsg << "<\n";
  ASSERT_TRUE( challmsg == expected.as_string() );

  return 1;
}
//----------------------------------------------------------------------
// DEFTEST( demo_test )
// {
//   jalson::json_array msg;
//   msg.append("hello");
//   jalson::json_value any = msg;
//   std::string encoding = jalson::encode( any );
//   std::cout << "encoding: " << encoding << "\n";

//   return 1;
// }

//----------------------------------------------------------------------
int main(int /*argc*/, char * /*argv*/ [])
{
  return autotest_runall();
}
