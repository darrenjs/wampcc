#include "wampcc/json.h"
#include <iostream>
#include <stdexcept>
#include <list>


#include "mini_test.h"

class MyType
{
};

//----------------------------------------------------------------------
TEST_CASE( "basic_json_object" )
{
  wampcc::json_value temp(1);
}


//----------------------------------------------------------------------
TEST_CASE( "jsonarray_basic_append" )
{
  // test array addition, and functions which append
  wampcc::json_array msg;

  msg.push_back( 0 );
  msg.push_back( 1 );
  msg.push_back("string");
  msg.push_back( true );

  wampcc::json_append<wampcc::json_array>(msg).push_back("a");
  wampcc::json_append<wampcc::json_object>(msg)["b"] = "c";

  std::string enc  = wampcc::json_encode(msg) ;
  std::cout << enc << "\n";
  REQUIRE(enc == "[0, 1, \"string\", true, [\"a\"], {\"b\": \"c\"}]");
}

//----------------------------------------------------------------------
TEST_CASE( "convert_type_to_string" )
{
  wampcc::json_value any1("should be string");
  wampcc::json_string str1 = any1.as_string();
  wampcc::json_value any2 = any1;
  wampcc::json_string str2 = any1.as_string();

  wampcc::json_value any3;
  any3.swap(any1);
  wampcc::json_string str3 = any3.as_string();

  REQUIRE( (str1 == str1) and (str1 == str3) );
}

//----------------------------------------------------------------------
TEST_CASE( "size_of" )
{
  //std::cout << "sizeof(JSONNumber) : " << sizeof(wampcc::JSONNumber) << "\n";
  std::cout << "sizeof(json_array) : " << sizeof(wampcc::json_array) << "\n";
  std::cout << "sizeof(value) : " << sizeof(wampcc::internals::valueimpl) << "\n";
}


//----------------------------------------------------------------------
TEST_CASE( "misc_operations" )
{
  wampcc::json_array ar1;

  wampcc::json_append(ar1, 100);
  wampcc::json_append(ar1, "mystring");

  wampcc::json_value acopy = wampcc::json_value( ar1 );
  wampcc::json_array ar2 = acopy.as<wampcc::json_array>();


  //MyType ar3 = acopy.as< MyType >();

  wampcc::json_value i1 = ar2[1];
  wampcc::json_string s1 = i1.as<wampcc::json_string>();

  REQUIRE (s1 == "mystring");
}

//----------------------------------------------------------------------

TEST_CASE( "encoding_call_message" )
{
  const std::string foreign_sid = "a1";
  const std::string foreign_rpc = "myrpc";
  int reqid = 100;

  wampcc::json_array msg;
  wampcc::json_append(msg, "call");
  wampcc::json_append<wampcc::json_object>(msg);
  wampcc::json_append(msg, foreign_sid + ":" +foreign_rpc);
  wampcc::json_append(msg, reqid);
  wampcc::json_append<wampcc::json_object>(msg);

  msg.push_back( 50.25 );

  wampcc::json_value any = msg;
  std::string encoding = wampcc::json_encode( any );
  //std::cout << "encoding: " << encoding << "\n";

  REQUIRE(encoding=="[\"call\", {}, \"a1:myrpc\", 100, {}, 50.25]");
}

wampcc::json_value takecopy(const wampcc::json_value& src)
{
  wampcc::json_value temp(0);
  temp = src;
  return temp;
}

//----------------------------------------------------------------------
TEST_CASE( "support_for_various_int_types" )
{
  wampcc::json_array msg;

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


  wampcc::json_value any = takecopy(msg); // test a copy too
  std::string encoding = wampcc::json_encode( any );
  std::cout << "encoding: " << encoding << "\n";

  REQUIRE( encoding=="[0, 1, 2, 3, 5, 6, 7, 0, \"x\"]");
}

//----------------------------------------------------------------------
TEST_CASE( "test_operator_eq" )
{
  wampcc::json_array msg(10);

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

  REQUIRE( msg[0].is_number() );
  REQUIRE( msg[2].is_bool() );
  REQUIRE( msg[2].is_true() );
  REQUIRE( msg[3].is_bool() );
  REQUIRE( msg[3].is_false() );
  REQUIRE( msg[4].is_string() );

  wampcc::json_value any = msg;
  std::string encoding = wampcc::json_encode( any );
  std::cout << "encoding: " << encoding << "\n";

//  check( );

//   return encoding=="[0, 10, 2, 3, 4]";
}


TEST_CASE( "map_examples" )
{
  wampcc::json_value a = wampcc::json_value::make_array();

  a.as<wampcc::json_array>().push_back(wampcc::json_value::make_object());
  wampcc::json_append<wampcc::json_array>( a.as<wampcc::json_array>() );
  auto & obj = wampcc::json_append<wampcc::json_object>( a.as<wampcc::json_array>() );

  obj["a"]=0;
  obj["b"]=1;
  obj["c"]=-1;
  obj["d"]="hello";
  obj["e"]= wampcc::json_value::make_object();
  wampcc::json_object& obj2 = wampcc::json_insert<wampcc::json_object>(obj, "X");
  /*wampcc::json_array& arr2  =*/ wampcc::json_insert<wampcc::json_array>(obj2, "X");
  std::string encoding = wampcc::json_encode( a );
  std::cout << "encoding: " << encoding << "\n";
}

TEST_CASE ( "encoding_example_1" )
{
  const char* src="[\"SUBSCRIBE\", 0, {}, \"T1\"]";
  wampcc::json_value a;
  wampcc::json_decode(a, src);

  wampcc::json_array msg=a.as<wampcc::json_array>();
  wampcc::json_value        reqid = msg.at(1);
  wampcc::json_object       opt = msg.at(2).as<wampcc::json_object>();
  wampcc::json_string topicname = msg.at(3).as<wampcc::json_string>();
}


TEST_CASE( "int_and_uint_and_real" )
{
  const char* src="[0, -1, 1, 1.25, \"x\" ]";
  wampcc::json_value a;
  wampcc::json_decode(a, src);

  wampcc::json_array& msg=a.as<wampcc::json_array>();

  REQUIRE( msg[0].is_uint() );
  REQUIRE( msg[0].is_int() );
  REQUIRE( msg[1].is_int() );
  REQUIRE ( msg[1].is_uint() == false );
  REQUIRE( msg[2].is_int() );
  REQUIRE( msg[2].is_uint() );
  REQUIRE( msg[3].is_number() );
  REQUIRE( msg[3].is_real() );
  REQUIRE( msg[3].as_real() ==  1.25 );
  REQUIRE( !msg[4].is_number() );
  REQUIRE( msg[4].is_string() );
  REQUIRE( !msg[4].is_object() );
  REQUIRE( !msg[4].is_array() );
}


TEST_CASE( "compiler_check" )
{
  /* here we are just checking that various expressions involving construction
   * and assignment which use primitive integer types, actually compile */
  {
    wampcc::json_value value;
    value = 0;
    value = 1;
    value = "0";
    value = wampcc::json_value::make_null();
    value = wampcc::json_string();
    value = wampcc::json_array();
    value = wampcc::json_object();
  }
  {
    char v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    short v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    signed char v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    signed short v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    unsigned char v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    unsigned short v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    int v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    int v = 0;
    wampcc::json_value value( v );
    value = v;
    value = wampcc::json_value::make_int(v);
  }
  {
    long v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    long long v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    bool v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  {
    const char* v = 0;
    wampcc::json_value value( v );
    value = v;
  }
  // {
  //   float * v = 0;
  //   wampcc::json_value value( v ); // error!
  //   value = v;
  // }
  // {
  //   double * v = 0;
  //   wampcc::json_value value( v ); // error!
  //   value = v;
  // }
  {
    std::string  v("test");
    wampcc::json_value value( v );
    value = v;
  }
  {
    const char*  v = "test";
    wampcc::json_value value( v );
    value = v;
  }
}

//----------------------------------------------------------------------
TEST_CASE( "copy_memleak" )
{

  wampcc::json_value jv;

  wampcc::json_array ja;
  ja.push_back( "hello" );
  ja.push_back( "world" );   //TODO: why do I not see thi value arrise at the other side? Jalson error?

  jv = ja ;
  wampcc::json_value jv2 = jv;

  std::cout << "encoding: " << wampcc::json_encode_any( jv2 ) << "\n";
}

//----------------------------------------------------------------------
TEST_CASE( "equality" )
{
  wampcc::json_value j1 = wampcc::json_decode( "{ \"foo\": [50, 20, 30, 40]} " );
  wampcc::json_value j2 = wampcc::json_decode( "{ \"foo\": [10, 20, 30, 40]} " );
  wampcc::json_value j3 = wampcc::json_decode( "{ \"foo\": [10, 20, 30, 40]} " );

  REQUIRE( j1 == j1 );
  REQUIRE( (j1 != j1) == false );
  REQUIRE( j1 != j2 );
  REQUIRE( (j1 == j2) == false );
  REQUIRE( j2 == j3 );
  REQUIRE( (j2 != j3) == false );


  wampcc::json_value j4 = wampcc::json_decode( "{ \"foo\": [1.1, 2.2 ], \"a\": true }" );
  wampcc::json_value j5 = wampcc::json_decode( "{ \"foo\": [1.2, 2.3 ], \"a\": true }" );
  wampcc::json_value j6 = wampcc::json_decode( "{ \"a\":true, \"foo\": [1.1, 2.2 ] }" );

  REQUIRE( j4 == j4 );
  REQUIRE( j4 != j5 );
  REQUIRE( (j4 == j5) == false );
  REQUIRE( j4 == j6 );

  wampcc::json_value j7 = wampcc::json_decode( "{ \"foo\": [-50, -20, -30, -40]} " );
  wampcc::json_value j8 = wampcc::json_decode( "{ \"foo\": [-10, -20, -30, -40]} " );
  wampcc::json_value j9 = wampcc::json_decode( "{ \"foo\": [-10, -20, -30, -40]} " );

  REQUIRE( j7 == j7 );
  REQUIRE( (j7 != j7) == false );
  REQUIRE( j7 != j8 );
  REQUIRE( (j7 == j8) == false );
  REQUIRE( j8 == j9 );
  REQUIRE( (j8 != j9) == false );

  wampcc::json_value j10 = wampcc::json_decode( "{ \"foo\": [true, false, true, false ]} " );
  wampcc::json_value j11 = wampcc::json_decode( "{ \"foo\": [true, false, true, true  ]} " );
  wampcc::json_value j12 = wampcc::json_decode( "{ \"foo\": [true, false, true, true  ]} " );

  REQUIRE( j10 == j10 );
  REQUIRE( (j10 != j10) == false );
  REQUIRE( j10 != j11 );
  REQUIRE( (j10 == j11) == false );
  REQUIRE( j11 == j12 );
  REQUIRE( (j11 != j12) == false );
}

//----------------------------------------------------------------------
TEST_CASE( "getters_api" )
{
  const wampcc::json_value j1 = wampcc::json_decode( "{ \"foo\": [50, 20, 30, 40]} " );

  const wampcc::json_object msg;


  const wampcc::json_value * id  = wampcc::json_get_ptr(msg, "id");
  REQUIRE( id == NULL);
  // const wampcc::json_value & id2 = wampcc::get_ref(msg, "id");

  const wampcc::json_value & id4 = wampcc::json_get_copy(msg, "id", wampcc::json_value::make_string("hello"));
  REQUIRE( id4 == wampcc::json_value::make_string("hello") );

  bool id5_exception_thrown=false;
  try
  {
    wampcc::json_get_ref(msg, "id");
  }
  catch (wampcc::field_not_found& e)
  {
    id5_exception_thrown = true;
  }
  REQUIRE(id5_exception_thrown);

  const wampcc::json_value expected = wampcc::json_value::make_string("xyz");
  std::string challmsg = wampcc::json_get_copy(msg, "challenge", "xyz").as_string();
  std::cout << "challmsg: >" << challmsg << "<\n";
  REQUIRE( challmsg == expected.as_string() );
}
//----------------------------------------------------------------------
TEST_CASE( "compare_unint_and_int" )
{
  // Check that an int(0) is equal to a uint(0), etc

  // TODO: add some more tests here

  REQUIRE(wampcc::json_value::make_int(-1) != wampcc::json_value::make_uint(-1));
  REQUIRE(wampcc::json_value::make_int(0) == wampcc::json_value::make_uint(0));
  REQUIRE(wampcc::json_value::make_int(1) == wampcc::json_value::make_uint(1));
  REQUIRE(wampcc::json_value::make_uint(0) == wampcc::json_value::make_int(0));
  REQUIRE(wampcc::json_value::make_uint(1) == wampcc::json_value::make_int(1));
}

//----------------------------------------------------------------------
// TEST_CASE( demo_test )
// {
//   wampcc::json_array msg;
//   msg.append("hello");
//   wampcc::json_value any = msg;
//   std::string encoding = wampcc::encode( any );
//   std::cout << "encoding: " << encoding << "\n";

//   return 1;
// }

//----------------------------------------------------------------------

int main(int argc, char** argv)
{
  try {
    int result = minitest::run(argc, argv);
    return (result < 0xFF ? result : 0xFF );
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
    return 1;
  }
}
