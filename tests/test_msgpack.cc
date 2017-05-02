#include "wampcc/json.h"
#include <iostream>
#include <stdexcept>
#include <list>

#include "testcase.h"

wampcc::json_value create_input_object()
{
  wampcc::json_object jv {
    {"k00",wampcc::json_value::make_null()},
    {"k01",wampcc::json_value::make_array()},
    {"k02",wampcc::json_value::make_object()},
    {"k03",wampcc::json_value::make_string("hello")},
    {"k04",wampcc::json_value::make_string("")},
    {"k05",wampcc::json_value::make_bool(true)},
    {"k06",wampcc::json_value::make_bool(false)},
    {"k07",wampcc::json_value::make_int(-99)},
    {"k08",wampcc::json_value::make_int(0)},
    {"k09",wampcc::json_value::make_int(99)},
    {"k10",wampcc::json_value::make_uint(0)},
    {"k11",wampcc::json_value::make_uint(99)},
    {"k12",wampcc::json_value::make_double(0.0)},
    {"k13",wampcc::json_value::make_double(3.14)},
    {"k14",wampcc::json_object{{"o1",1},{"o2",2},{"o3",3}} },
    {"k15",wampcc::json_array{"a1",1,"a2",2,"a3",3}},
      };
  return jv;
}

wampcc::json_value create_input_array()
{
  wampcc::json_array jv {
      wampcc::json_value::make_null(),
      wampcc::json_value::make_array(),
      wampcc::json_value::make_object(),
      wampcc::json_value::make_string("hello"),
      wampcc::json_value::make_string(""),
      wampcc::json_value::make_bool(true),
      wampcc::json_value::make_bool(false),
      wampcc::json_value::make_int(-99),
      wampcc::json_value::make_int(0),
      wampcc::json_value::make_int(99),
      wampcc::json_value::make_uint(0),
      wampcc::json_value::make_uint(99),
      wampcc::json_value::make_double(0.0),
      wampcc::json_value::make_double(3.14),
      wampcc::json_object{{"o1",1},{"o2",2},{"o3",3}},
      wampcc::json_array{"a1",1,"a2",2,"a3",3},
      };
  return jv;
}

wampcc::json_array recurse_create_array(int depth)
{
  wampcc::json_array obj {
    create_input_array(),
    create_input_array(),
    wampcc::json_value::make_array(),
    wampcc::json_value::make_array() };

  if (depth>0)
    obj.push_back( recurse_create_array(depth-1) );
  else
    obj.push_back( wampcc::json_array() );

  return obj;
}

wampcc::json_object recurse_create_object(int depth)
{
  wampcc::json_object obj;
  obj.insert({"d01", create_input_object()});
  obj.insert({"d02", create_input_array()});
  obj.insert({"d03", wampcc::json_value::make_object()});
  obj.insert({"d04", wampcc::json_value::make_array()});

  if (depth>0)
    obj.insert({"d05", recurse_create_object(depth-1)});
  else
    obj.insert({"d05", wampcc::json_object()});

  return obj;
}


std::list<wampcc::json_value> test_inputs()
{
  std::list<wampcc::json_value> rv;

  rv.push_back(wampcc::json_value::make_null());
  rv.push_back(wampcc::json_value::make_array());
  rv.push_back(wampcc::json_value::make_object());
  rv.push_back(wampcc::json_value::make_string(""));
  rv.push_back(wampcc::json_value::make_string("hello"));
  rv.push_back(wampcc::json_value::make_bool(true));
  rv.push_back(wampcc::json_value::make_bool(false));
  rv.push_back(wampcc::json_value::make_int(-99));
  rv.push_back(wampcc::json_value::make_int(0));
  rv.push_back(wampcc::json_value::make_int(99));
  rv.push_back(wampcc::json_value::make_uint(0));
  rv.push_back(wampcc::json_value::make_uint(99));
  rv.push_back(wampcc::json_value::make_double(0.0));
  rv.push_back(wampcc::json_value::make_double(3.14));
  rv.push_back(create_input_array());
  rv.push_back(create_input_object());
  rv.push_back(recurse_create_object(0));
  rv.push_back(recurse_create_object(1));
  rv.push_back(recurse_create_object(10));
  rv.push_back(recurse_create_object(100));
  rv.push_back(recurse_create_array(0));
  rv.push_back(recurse_create_array(1));
  rv.push_back(recurse_create_array(10));
  rv.push_back(recurse_create_array(100));

  return rv;
}

void test_json_value(const wampcc::json_value& src)
{
  auto bytes = wampcc::json_msgpack_encode(src);

  auto dest = wampcc::json_msgpack_decode(bytes->first, bytes->second);

  ASSERT_TRUE(src == dest);
}

DEFTEST( msgpack_encode_decode )
{
  auto tests = test_inputs();

  for (auto & item : test_inputs())
    test_json_value( item );

  return 1;
}

int main(int /*argc*/, char * /*argv*/ [])
{
  return autotest_runall();
}
