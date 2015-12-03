#include "jalson/jalson.h"
#include <iostream>
#include <stdexcept>
#include <list>


#define ASSERT_TRUE( X )                                               \
  do                                                                   \
  {                                                                    \
  bool b( X );                                                         \
  if (!b)                                                              \
  {                                                                    \
    throw std::runtime_error( "ASSERT_TRUE( " #X " ) failed" );        \
  }                                                                    \
  } while (false)

#define ASSERT_EQ( X, Y )                                               \
  if (X != Y)                                                           \
  {                                                                     \
    throw std::runtime_error( "ASSERT_EQ( "#X ", " #Y  ") failed" );    \
  }                                                                     \


class testcasebase;

std::list< testcasebase* > global_test_reg;


struct TestResult
{
  std::string testname;
  enum Result { Fail, Pass } result;


  TestResult() : result(Fail) {}
  TestResult(const std::string& name,
             bool passed)
    : testname(name),
      result(passed? Pass: Fail)
  {
  }

  const char* result_str() const
  {
    switch (result)
    {
      case Fail : return "fail";
      case Pass : return "pass";
      default   : return "unknown";
    }
  }

  void result_dump() const
  {
    std::cout << "[";
    switch (result)
    {
      case Fail : std::cout << "\033[1;31m"; break;
      case Pass : std::cout << "\033[1;32m"; break;
    }

    std::cout << result_str();
    std::cout << "\033[0m";
    std::cout << "] " << testname << "\n";
  }

};

class testcasebase
{
public:
  testcasebase()
  {
    global_test_reg.push_back( this );
  }
  virtual int impl() = 0;
  virtual const char* testname() const = 0;

  TestResult run()
  {
    std::string msg;
    int retval;
    try
    {
      std::cout << "\n[test] testing: " << testname() << " ...\n";
      retval = this->impl();
      if (!retval)
      {
        // std::cout << "result : " << testname() << "  -- ";
        // std::cout << "failed: retval=" << retval << "\n";
        std::cout << "[fail] " << testname() <<  " retval=" <<retval<< "\n";

        return TestResult(testname(), false);
      }
      else
      {
//        std::cout << "result : " << testname() << "  -- ";
        std::cout << "[pass] " << testname() << "\n";
        return TestResult(testname(), true);
      }
    }
    catch (const std::exception& e)
    {
      std::cout <<  "failed: exception: " << e.what() << "\n";
      return TestResult(testname(), false);
    }
    catch (...)
    {
      std::cout <<  "failed: unknown exception" << "\n";
      return TestResult(testname(), false);
    }

  }
};

void banner(bool prenewline=false)
{
  if (prenewline) std::cout << "\n";
  std::cout << "========================================\n";
}

void autotest_runall()
{
  banner();
  std::cout << "Transcript\n";
  banner();
  std::vector< TestResult > results;
  for (std::list< testcasebase* >::iterator i = global_test_reg.begin();
       i != global_test_reg.end(); ++i)
  {
    testcasebase* ptr = *i;
    results.push_back( ptr->run() );
  }

  banner(true);
  std::cout << "Results\n";
  banner();

  int count_tests = 0;
  int count_pass  = 0;
  int count_fail  = 0;
  for (std::vector< TestResult >::iterator it = results.begin();
       it != results.end(); ++it)
  {
    it->result_dump();
    count_tests++;
    count_pass += it->result==TestResult::Pass;
    count_fail += it->result==TestResult::Fail;
  }

  banner(true);
  std::cout << "Summary\n";
  banner();
  std::cout << "total " << count_tests << "\n";
  std::cout << "pass  " << count_pass << "\n";
  std::cout << "fail  " << count_fail << "\n";
}


#define  DEFTEST( X )                                  \
  int X () ;                                           \
  class testcase__ ## X : public testcasebase          \
  {                                                    \
    int impl()                                         \
    {                                                  \
      return X();                                      \
    }                                                  \
    const char* testname() const                       \
    {                                                  \
      return #X;                                       \
    }                                                  \
  };                                                   \
  testcase__ ## X mytest_ ## X;                   \
  int X ()


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

  jalson::append_array(msg).push_back("a");
  jalson::append_object(msg)["b"] = "c";

  std::string enc  = jalson::to_string(msg) ;
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

  jalson::append(ar1, 100);
  jalson::append(ar1, "mystring");

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
  jalson::append(msg, "call");
  jalson::append_object(msg);
  jalson::append(msg, foreign_sid + ":" +foreign_rpc);
  jalson::append(msg, reqid);
  jalson::append_object(msg);




  //msg.append< MyType >();   // TODO: how can this work?
  msg.push_back( 50.25 );

  jalson::json_value any = msg;
  std::string encoding = jalson::encode( any );
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
  std::string encoding = jalson::encode( any );
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
  std::string encoding = jalson::encode( any );
  std::cout << "encoding: " << encoding << "\n";

//  check( );

//   return encoding=="[0, 10, 2, 3, 4]";
  return true;
}


DEFTEST( map_examples )
{
  jalson::json_value a = jalson::json_value::make_array();

  a.as<jalson::json_array>().push_back(jalson::json_value::make_object());
  jalson::append_array( a.as<jalson::json_array>() );
  jalson::json_object& obj = jalson::append_object( a.as<jalson::json_array>() );

  obj["a"]=0;
  obj["b"]=1;
  obj["c"]=-1;
  obj["d"]="hello";
  obj["e"]= jalson::json_value::make_object();
  jalson::json_object& obj2 = jalson::insert_object(obj, "X");
  /*jalson::json_array& arr2  =*/ jalson::insert_array(obj2, "X");
  std::string encoding = jalson::encode( a );
  std::cout << "encoding: " << encoding << "\n";

  return 1;
}

DEFTEST ( encoding_example_1 )
{
  const char* src="[\"SUBSCRIBE\", 0, {}, \"T1\"]";
  jalson::json_value a;
  jalson::decode(a, src);

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
  jalson::decode(a, src);

  jalson::json_array& msg=a.as<jalson::json_array>();

  ASSERT_TRUE( msg[0].is_uint() );
  ASSERT_TRUE( msg[0].is_sint() );
  ASSERT_TRUE( msg[1].is_sint() );
  ASSERT_EQ  ( msg[1].is_uint(),false );
  ASSERT_TRUE( msg[2].is_sint() );
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
  {
    float * v = 0;
    jalson::json_value value( v );
    value = v;
  }
  {
    double * v = 0;
    jalson::json_value value( v );
    value = v;
  }
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
  autotest_runall();
}
