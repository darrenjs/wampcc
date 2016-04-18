
#include "jalson/jalson.h"

#include "testcase.h"

//----------------------------------------------------------------------
DEFTEST( test_basic_int )
{

  jalson::json_value jv_1(1);
  ASSERT_TRUE( jv_1.is_int() );
  ASSERT_TRUE( jv_1.is_uint() );

  jalson::json_value jv_0(0);
  ASSERT_TRUE( jv_0.is_int() );
  ASSERT_TRUE( jv_0.is_uint() );

  jalson::json_value jv_n1(-1);
  ASSERT_TRUE( jv_n1.is_int() == true );
  ASSERT_TRUE( jv_n1.is_uint() == false );

  {

    jalson::json_value jv = jalson::json_value::make_uint( ~0 );
    ASSERT_TRUE( jv.is_int() == false);
    ASSERT_TRUE( jv.is_uint() == true );
  }

  {
    jalson::json_value jv = jalson::json_value::make_uint(0);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.as_int() == 0);
  }

  {
    jalson::json_value jv = jalson::json_value::make_uint(2147483647);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.as_int() == 2147483647);
  }

  {
    jalson::json_value jv(1);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == true );
    ASSERT_TRUE( jv.is_uint8() == true );
    ASSERT_TRUE( jv.is_int16() == true );
    ASSERT_TRUE( jv.is_uint16() == true );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv(32767);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == true );
    ASSERT_TRUE( jv.is_uint16() == true );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv(32767+1);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == false );
    ASSERT_TRUE( jv.is_uint16() == true );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv(65535);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == false );
    ASSERT_TRUE( jv.is_uint16() == true );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv(65535+1);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == false );
    ASSERT_TRUE( jv.is_uint16() == false );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv(2147483647);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == false );
    ASSERT_TRUE( jv.is_uint16() == false );
    ASSERT_TRUE( jv.is_int32() == true );
    ASSERT_TRUE( jv.is_uint32() == true );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv( 2147483648UL );
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == true );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == false );
    ASSERT_TRUE( jv.is_uint16() == false );
    ASSERT_TRUE( jv.is_int32() == false );
    ASSERT_TRUE( jv.is_uint32() == true );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == true );
  }

  {
    jalson::json_value jv( -1 );
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == false );
    ASSERT_TRUE( jv.is_int8() == true );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == true );
    ASSERT_TRUE( jv.is_uint16() == false );
    ASSERT_TRUE( jv.is_int32() == true );
    ASSERT_TRUE( jv.is_uint32() == false );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == false );
  }

  {
    jalson::json_value jv(-32768);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == false );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == true );
    ASSERT_TRUE( jv.is_uint16() == false );
    ASSERT_TRUE( jv.is_int32() == true );
    ASSERT_TRUE( jv.is_uint32() == false );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == false );
  }

  {
    jalson::json_value jv(-32769);
    ASSERT_TRUE( jv.is_int() == true );
    ASSERT_TRUE( jv.is_uint() == false );
    ASSERT_TRUE( jv.is_int8() == false );
    ASSERT_TRUE( jv.is_uint8() == false );
    ASSERT_TRUE( jv.is_int16() == false );
    ASSERT_TRUE( jv.is_uint16() == false );
    ASSERT_TRUE( jv.is_int32() == true );
    ASSERT_TRUE( jv.is_uint32() == false );
    ASSERT_TRUE( jv.is_int64() == true );
    ASSERT_TRUE( jv.is_uint64() == false );
  }

  return 1;
}

//----------------------------------------------------------------------
int main(int /*argc*/, char * /*argv*/ [])
{
  return autotest_runall();
}
