/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "json_pointer.cc"

#include "mini_test.h"

using namespace wampcc;

//----------------------------------------------------------------------

bool test_has_escape_seq(const char* p)
{
  return has_escape_seq(p, p+strlen(p));
}

TEST_CASE( "has_escape_seq" )
{
  REQUIRE( test_has_escape_seq("") == 0);
  REQUIRE( test_has_escape_seq("xxx") == 0);
  REQUIRE( test_has_escape_seq("~") == 0);
  REQUIRE( test_has_escape_seq(" ~ 1 ") == 0);
  REQUIRE( test_has_escape_seq("~/") == 0);
  REQUIRE( test_has_escape_seq("   ~ 0") == 0);

  REQUIRE( test_has_escape_seq("~0") != 0);
  REQUIRE( test_has_escape_seq(" ~0") != 0);
  REQUIRE( test_has_escape_seq("   ~0") != 0);
  REQUIRE( test_has_escape_seq("~1") != 0);
  REQUIRE( test_has_escape_seq("~1 ") != 0);
  REQUIRE( test_has_escape_seq(" ~~1 ") != 0);
}

//----------------------------------------------------------------------

bool test_pointer_success(json_value doc, std::string path, json_value expected)
{
  try
  {
    operation<nonconst_variant> op(opcode::eRead);
    apply_single_patch(doc, path, &op);
    return (*op.read_only == expected);
  }
  catch (const bad_pointer& e)
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
bool test_bad_pointer(json_value doc, std::string path)
{
  try
  {
    operation<nonconst_variant> op(opcode::eRead);
    apply_single_patch(doc, path, &op);
    return false;  // we expected fail
  }
  catch (const bad_pointer& e)
  {
    std::cout << "xfail: " << e.what() << ", pathindex " << e.path_index << "\n";

  }
  catch (const std::runtime_error& e)
  {
    std::cout << "xfail: " << e.what() << "\n";

  }
  return true;
}



TEST_CASE( "test_example" )
{
  const char* jsonstr="\
   {                                            \
      \"foo\": [\"bar\", \"baz\",[10,20,30]],   \
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
  json_value doc=json_decode(jsonstr);


  REQUIRE( test_pointer_success(doc, "",       doc) ); // full doc match
  REQUIRE( test_pointer_success(doc, "/foo",   json_decode("[\"bar\", \"baz\",[10,20,30]]")));
  REQUIRE( test_pointer_success(doc, "/foo/0", json_value::make_string("bar")));
  REQUIRE( test_pointer_success(doc, "/",      json_value::make_int(0)));
  REQUIRE( test_pointer_success(doc, "/a~1b",  json_value::make_int(1)));
  REQUIRE( test_pointer_success(doc, "/c%d",   json_value::make_int(2)));
  REQUIRE( test_pointer_success(doc, "/e^f",   json_value::make_int(3)));
  REQUIRE( test_pointer_success(doc, "/g|h",   json_value::make_int(4)));
  REQUIRE( test_pointer_success(doc, "/i\\j",  json_value::make_int(5)));
  REQUIRE( test_pointer_success(doc, "/k\"l",  json_value::make_int(6)));
  REQUIRE( test_pointer_success(doc, "/ ",     json_value::make_int(7)));
  REQUIRE( test_pointer_success(doc, "/m~0n",  json_value::make_int(8)));

  REQUIRE( test_bad_pointer(doc, "/foo//" ));
  REQUIRE( test_bad_pointer(doc, "/foo/01" ));
  REQUIRE( test_bad_pointer(doc, "/foo/01/0" ));
  REQUIRE( test_bad_pointer(doc, "/foo/00" ));
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

TEST_CASE( "expand_escaped_chars" )
{
  REQUIRE( test_expand_escaped_chars("","") );

  REQUIRE( test_expand_escaped_chars("",""));
  REQUIRE( test_expand_escaped_chars("~~~~","~~~~"));
  REQUIRE( test_expand_escaped_chars("~","~"));
  REQUIRE( test_expand_escaped_chars("~0","~"));
  REQUIRE( test_expand_escaped_chars("~1","/"));
  REQUIRE( test_expand_escaped_chars("abc","abc"));
  REQUIRE( test_expand_escaped_chars("abc~0~","abc~~"));
  REQUIRE( test_expand_escaped_chars("abc~0~1","abc~/"));
  REQUIRE( test_expand_escaped_chars("abc~0x~1","abc~x/"));
  REQUIRE( test_expand_escaped_chars("~~~0~1~0~1~~","~~~/~/~~"));
  REQUIRE( test_expand_escaped_chars("~00~01","~0~1"));
}

//----------------------------------------------------------------------

bool patch_test(const char* docstr, const char* patchstr, const char * expectstr)
{
  if (expectstr == 0) expectstr=docstr;
  json_value doc=json_decode(docstr);
  json_value orig = doc;
  json_array patch=json_decode(patchstr).as_array();
  json_value expect=json_decode(expectstr);
  bool result = apply_patch(doc, patch);

  if (result == false) return false;

  bool equal = (doc == expect);

  if (!equal)
  {
    std::cout << "doc: '" << orig << "'\n"
              << "patch: '" << patch << "'\n"
              << "expect: '" << expect << "'\n"
              << "actual: '" << doc << "'\n";
  }
   return equal;
}

bool patch_test_fail(const char* docstr, const char* patchstr)
{
  json_value doc=json_decode(docstr);
  json_value orig = doc;
  json_array patch=json_decode(patchstr).as_array();
  bool result = apply_patch(doc, patch);

  std::cout << "doc: '" << orig << "'\n"
            << "patch: '" << patch << "'\n"
            << "actual: '" << doc << "'\n";

  return result == false; /* we exepct it to fail*/

}




TEST_CASE( "json_patch_rfc_examples_a1" )
{
  REQUIRE(
    patch_test(
      "{ \"foo\": \"bar\"}",
      "[{ \"op\": \"add\", \"path\": \"/baz\", \"value\": \"qux\" } ]",
      "{ \"baz\": \"qux\", \"foo\": \"bar\"}")
    );
}
TEST_CASE( "json_patch_rfc_examples_a2" )
{
  REQUIRE(
    patch_test(
      "  { \"foo\": [ \"bar\", \"baz\" ] } ",
      "  [  { \"op\": \"add\", \"path\": \"/foo/1\", \"value\": \"qux\" } ] ",
      "  { \"foo\": [ \"bar\", \"qux\", \"baz\" ] }   ")
    );
}
TEST_CASE( "json_patch_rfc_examples_a3" )
{
  // Removing an Object Member
  REQUIRE(
    patch_test(
      "   { \"baz\": \"qux\", \"foo\": \"bar\" } ",
      "   [ { \"op\": \"remove\", \"path\": \"/baz\" } ] " ,
      "   { \"foo\": \"bar\" } ")
    );
}
TEST_CASE( "json_patch_rfc_examples_a4" )
{
  // Removing an Array Element
  REQUIRE(
    patch_test(
      " { \"foo\": [ \"bar\", \"qux\", \"baz\" ] }  ",
      "  [ { \"op\": \"remove\", \"path\": \"/foo/1\" } ]   " ,
      "  { \"foo\": [ \"bar\", \"baz\" ] } ")
    );
}
TEST_CASE( "json_patch_rfc_examples_a5" )
{
  // Replacing a Value
  REQUIRE(
    patch_test(
      "  {  \"baz\": \"qux\", \"foo\": \"bar\" }  ",
      "  [ { \"op\": \"replace\", \"path\": \"/baz\", \"value\": \"boo\" } ]   " ,
      "  { \"baz\": \"boo\", \"foo\": \"bar\" }  ")
    );
  REQUIRE(
    patch_test(
      "  { \"foo\": [ \"bar\", \"qux\", \"baz\" ] } ",
      "  [ { \"op\": \"replace\", \"path\": \"/foo/1\", \"value\": \"boo\" } ] " ,
      "  { \"foo\": [ \"bar\", \"boo\", \"baz\" ] } ")
    );
}
TEST_CASE( "json_patch_rfc_examples_a6" )
{
  // Moving a Value
  REQUIRE(
    patch_test(
      "  { \"foo\": { \"bar\": \"baz\", \"waldo\": \"fred\" }, \"qux\": { \"corge\": \"grault\"  } }  ",
      "  [ { \"op\": \"move\", \"from\": \"/foo/waldo\", \"path\": \"/qux/thud\" } ] " ,
      "  {  \"foo\": { \"bar\": \"baz\" }, \"qux\": { \"corge\": \"grault\", \"thud\": \"fred\"  }  } ")
    );

  // TODO: add an array test
}

TEST_CASE( "json_patch_rfc_examples_a7" )
{
  // Moving an Array Element
  REQUIRE(
    patch_test(
      "  { \"foo\": [ \"all\", \"grass\", \"cows\", \"eat\" ] }  ",
      "  [ { \"op\": \"move\", \"from\": \"/foo/1\", \"path\": \"/foo/3\" } ]  " ,
      "  { \"foo\": [ \"all\", \"cows\", \"eat\", \"grass\" ] } ")
    );
}

TEST_CASE( "json_patch_rfc_examples_a8" )
{
  // Testing a Value: Success
  REQUIRE(
    patch_test(
      "  { \"baz\": \"qux\", \"foo\": [ \"a\", 2, \"c\" ] } ",
      "  [ { \"op\": \"test\", \"path\": \"/baz\", \"value\": \"qux\" }, { \"op\": \"test\", \"path\": \"/foo/1\", \"value\": 2 } ]  " ,
      "  { \"baz\": \"qux\", \"foo\": [ \"a\", 2, \"c\" ] } ")
    );
}

TEST_CASE( "json_patch_rfc_examples_a9" )
{
  REQUIRE(
    patch_test_fail(
      " { \"baz\": \"qux\" }  ",
      " [ { \"op\": \"test\", \"path\": \"/baz\", \"value\": \"bar\" } ] ")
    );
}

TEST_CASE( "json_patch_rfc_examples_a10" )
{
  // Adding a Nested Member Object
  REQUIRE(
    patch_test(
      "  { \"foo\": \"bar\" } ",
      "  [ { \"op\": \"add\", \"path\": \"/child\", \"value\": { \"grandchild\": { } } } ]  " ,
      "  { \"foo\": \"bar\", \"child\": { \"grandchild\": { } } }")
    );
}


TEST_CASE( "json_patch_rfc_examples_a11" )
{
  // Ignoring Unrecognized Elements
  REQUIRE(
    patch_test(
      "   { \"foo\": \"bar\" }  ",
      "   [ { \"op\": \"add\", \"path\": \"/baz\", \"value\": \"qux\", \"xyz\": 123 } ]  " ,
      "   { \"foo\": \"bar\", \"baz\": \"qux\" } ")
    );
}


TEST_CASE( "json_patch_rfc_examples_a12" )
{
  // Adding to a Nonexistent Target
  REQUIRE(
    patch_test_fail(
      " { \"foo\": \"bar\" }  ",
      " [ { \"op\": \"add\", \"path\": \"/baz/bat\", \"value\": \"qux\" } ] " )
    );
}


// TEST_CASE( json_patch_rfc_examples_a13)
// {
//   REQUIRE(
//     patch_test(
//       "   ",
//       "    " ,
//       "  ")
//     );

//   return 1;
// }


TEST_CASE( "json_patch_rfc_examples_a14" )
{
  // ~ Escape Ordering
  REQUIRE(
    patch_test(
      "  {  \"/\": 9, \"~1\": 10 }  ",
      "  [  {\"op\": \"test\", \"path\": \"/~01\", \"value\": 10} ]  " ,
      "  {  \"/\": 9, \"~1\": 10 } ")
    );
}


TEST_CASE( "json_patch_rfc_examples_a15" )
{
  REQUIRE(
    patch_test_fail(
      "  { \"/\": 9, \"~1\": 10  }  ",
      "  [ {\"op\": \"test\", \"path\": \"/~01\", \"value\": \"10\"} ]  ")
    );

}



TEST_CASE( "json_patch_rfc_examples_a16" )
{
  // Adding an Array Value
  REQUIRE(
    patch_test(
      " { \"foo\": [\"bar\"] } ",
      " [ { \"op\": \"add\", \"path\": \"/foo/-\", \"value\": [\"abc\", \"def\"] } ] " ,
      " { \"foo\": [\"bar\", [\"abc\", \"def\"]] } ")
    );
}



TEST_CASE( "json_patch_copy" )
{

  REQUIRE(
    patch_test(
      " { \"foo\": [\"bar\", \"baz\"] } ",
      " [ { \"op\": \"copy\", \"from\": \"/foo\", \"path\": \"/bar\" } ] " ,
      " { \"foo\": [\"bar\", \"baz\"] ,  \"bar\": [\"bar\", \"baz\"]  } ")
    );

  REQUIRE(
    patch_test(
      " { \"foo\": [\"bar\", \"baz\"] } ",
      " [ { \"op\": \"copy\", \"from\": \"/foo/1\", \"path\": \"/bar\" } ] " ,
      " { \"foo\": [\"bar\", \"baz\"] ,  \"bar\": \"baz\" } ")
    );
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
