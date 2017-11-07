#include "wampcc/json.h"
#include <iostream>
#include <stdexcept>
#include <list>
#include <cstring>

#include "mini_test.h"

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

  REQUIRE(src == dest);
}

TEST_CASE( "msgpack_encode_decode" )
{
  auto tests = test_inputs();

  for (auto & item : test_inputs())
    test_json_value( item );
}

TEST_CASE( "msgpack_signed_integer_limits" )
{
  /* Check that msgpack encode & decode works with max and min signed
   * integers (github issue #6).*/
  uint8_t u8max = 255;
  uint16_t u16max = 65535;
  uint32_t u32max = 4294967295;
  auto i64max = (std::numeric_limits<long long>::max)(); //  9223372036854775807
  auto i64min = (std::numeric_limits<long long>::min)(); // -9223372036854775808

  wampcc::json_value jin = wampcc::json_value::make_array();
  jin.as_array().push_back(0);
  jin.as_array().push_back(50);
  jin.as_array().push_back(563234340645992);
  jin.as_array().push_back(u8max);
  jin.as_array().push_back(u16max);
  jin.as_array().push_back(u32max);
  jin.as_array().push_back(i64max);
  jin.as_array().push_back(i64min);

  // encode
  auto region = wampcc::json_msgpack_encode(jin);
  std::vector<char> retval(region->second);
  memcpy(retval.data(), region->first, region->second);

  // decode
  wampcc::json_value jout = wampcc::json_msgpack_decode(retval.data(), retval.size());

  // std::cout << "jin : " << jin << std::endl;
  // std::cout << "jout: " << jout << std::endl;
  REQUIRE(jin == jout);
}

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
