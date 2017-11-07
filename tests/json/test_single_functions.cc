
#include "wampcc/json.h"

#include "mini_test.h"

//----------------------------------------------------------------------

TEST_CASE( "test_basic_int" )
{
  wampcc::json_value jv_1(1);
  REQUIRE( jv_1.is_int() );
  REQUIRE( jv_1.is_uint() );

  wampcc::json_value jv_0(0);
  REQUIRE( jv_0.is_int() );
  REQUIRE( jv_0.is_uint() );

  wampcc::json_value jv_n1(-1);
  REQUIRE( jv_n1.is_int() == true );
  REQUIRE( jv_n1.is_uint() == false );

  {

    wampcc::json_value jv = wampcc::json_value::make_uint( ~0 );
    REQUIRE( jv.is_int() == false);
    REQUIRE( jv.is_uint() == true );
  }

  {
    wampcc::json_value jv = wampcc::json_value::make_uint(0);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.as_int() == 0);
  }

  {
    wampcc::json_value jv = wampcc::json_value::make_uint(2147483647);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.as_int() == 2147483647);
  }

  {
    wampcc::json_value jv(1);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == true );
    REQUIRE( jv.is_uint8() == true );
    REQUIRE( jv.is_int16() == true );
    REQUIRE( jv.is_uint16() == true );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv(32767);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == true );
    REQUIRE( jv.is_uint16() == true );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv(32767+1);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == false );
    REQUIRE( jv.is_uint16() == true );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv(65535);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == false );
    REQUIRE( jv.is_uint16() == true );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv(65535+1);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == false );
    REQUIRE( jv.is_uint16() == false );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv(2147483647);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == false );
    REQUIRE( jv.is_uint16() == false );
    REQUIRE( jv.is_int32() == true );
    REQUIRE( jv.is_uint32() == true );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv( 2147483648UL );
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == true );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == false );
    REQUIRE( jv.is_uint16() == false );
    REQUIRE( jv.is_int32() == false );
    REQUIRE( jv.is_uint32() == true );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == true );
  }

  {
    wampcc::json_value jv( -1 );
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == false );
    REQUIRE( jv.is_int8() == true );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == true );
    REQUIRE( jv.is_uint16() == false );
    REQUIRE( jv.is_int32() == true );
    REQUIRE( jv.is_uint32() == false );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == false );
  }

  {
    wampcc::json_value jv(-32768);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == false );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == true );
    REQUIRE( jv.is_uint16() == false );
    REQUIRE( jv.is_int32() == true );
    REQUIRE( jv.is_uint32() == false );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == false );
  }

  {
    wampcc::json_value jv(-32769);
    REQUIRE( jv.is_int() == true );
    REQUIRE( jv.is_uint() == false );
    REQUIRE( jv.is_int8() == false );
    REQUIRE( jv.is_uint8() == false );
    REQUIRE( jv.is_int16() == false );
    REQUIRE( jv.is_uint16() == false );
    REQUIRE( jv.is_int32() == true );
    REQUIRE( jv.is_uint32() == false );
    REQUIRE( jv.is_int64() == true );
    REQUIRE( jv.is_uint64() == false );
  }

}

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
