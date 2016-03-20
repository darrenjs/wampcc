/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <json_pointer.cc>

#include "testcase.h"

using namespace jalson;

//----------------------------------------------------------------------
DEFTEST( has_escape_seq )
{
  ASSERT_TRUE( has_escape_seq("") == 0);
  ASSERT_TRUE( has_escape_seq("xxx") == 0);
  ASSERT_TRUE( has_escape_seq("~") == 0);
  ASSERT_TRUE( has_escape_seq(" ~ 1 ") == 0);
  ASSERT_TRUE( has_escape_seq("~/") == 0);
  ASSERT_TRUE( has_escape_seq("   ~ 0") == 0);

  ASSERT_TRUE( has_escape_seq("~0") != 0);
  ASSERT_TRUE( has_escape_seq(" ~0") != 0);
  ASSERT_TRUE( has_escape_seq("   ~0") != 0);
  ASSERT_TRUE( has_escape_seq("~1") != 0);
  ASSERT_TRUE( has_escape_seq("~1 ") != 0);
  ASSERT_TRUE( has_escape_seq(" ~~1 ") != 0);

  return 1;
}

//----------------------------------------------------------------------

bool test_pointer_success(json_value doc, std::string path, json_value expected)
{
  try
  {
    json_value result = select(doc, path);
    return (result == expected);
  }
  catch (const pointer_fail& e)
  {
    std::cout << "FAILED: " << e.what() << ", pathindex " << e.path_index << "\n";
    return false;
  }
  catch (const std::runtime_error& e)
  {
    std::cout << "FAILED: " << e.what() << "\n";
    return false;
  }

}


DEFTEST( test_example )
{
  const char* jsonstr="\
   {                                            \
      \"foo\": [\"bar\", \"baz\"],              \
      \"\": 0,                                  \
      \"a/b\": 1,                               \
      \"c%d\": 2,                               \
      \"e^f\": 3,                               \
      \"g|h\": 4,                               \
      \"i\\\\j\": 5,                            \
      \"k\\\"l\": 6,                            \
      \" \": 7,                                 \
      \"m~n\": 8                                \
   }";
  json_value doc=decode(jsonstr);


  ASSERT_TRUE( test_pointer_success(doc, "",       doc) ); // full doc match
  ASSERT_TRUE( test_pointer_success(doc, "/foo",   decode("[\"bar\", \"baz\"]")));
  ASSERT_TRUE( test_pointer_success(doc, "/foo/0", json_value::make_string("bar")));
  ASSERT_TRUE( test_pointer_success(doc, "/",      json_value::make_int(0)));
  ASSERT_TRUE( test_pointer_success(doc, "/a~1b",  json_value::make_int(1)));
  ASSERT_TRUE( test_pointer_success(doc, "/c%d",   json_value::make_int(2)));
  ASSERT_TRUE( test_pointer_success(doc, "/e^f",   json_value::make_int(3)));
  ASSERT_TRUE( test_pointer_success(doc, "/g|h",   json_value::make_int(4)));
  ASSERT_TRUE( test_pointer_success(doc, "/i\\j",  json_value::make_int(5)));
  ASSERT_TRUE( test_pointer_success(doc, "/k\"l",  json_value::make_int(6)));
  ASSERT_TRUE( test_pointer_success(doc, "/ ",     json_value::make_int(7)));
  ASSERT_TRUE( test_pointer_success(doc, "/m~0n",  json_value::make_int(8)));

  return 1;
}

//----------------------------------------------------------------------

bool test_expand_escaped_chars(const char* src, const char* expected)
{
  char* dest= expand_str(src, src+strlen(src) );
  bool are_same = (strcmp(dest, expected)==0);
  if (!are_same)
  {
    std::cout << "expect: '" << expected << "'\n"
              << "actual: '" << dest << "'\n";
  }
  delete [] dest;
  return are_same;
}

DEFTEST( expand_escaped_chars )
{
  ASSERT_TRUE( test_expand_escaped_chars("","") );

  ASSERT_TRUE( test_expand_escaped_chars("",""));
  ASSERT_TRUE( test_expand_escaped_chars("~~~~","~~~~"));
  ASSERT_TRUE( test_expand_escaped_chars("~","~"));
  ASSERT_TRUE( test_expand_escaped_chars("~0","~"));
  ASSERT_TRUE( test_expand_escaped_chars("~1","/"));
  ASSERT_TRUE( test_expand_escaped_chars("abc","abc"));
  ASSERT_TRUE( test_expand_escaped_chars("abc~0~","abc~~"));
  ASSERT_TRUE( test_expand_escaped_chars("abc~0~1","abc~/"));
  ASSERT_TRUE( test_expand_escaped_chars("abc~0x~1","abc~x/"));
  ASSERT_TRUE( test_expand_escaped_chars("~~~0~1~0~1~~","~~~/~/~~"));
  ASSERT_TRUE( test_expand_escaped_chars("~00~01","~0~1"));

  return 1;
}

//----------------------------------------------------------------------



int main(int /*argc*/, char * /*argv*/ [])
{
  return autotest_runall();
}
