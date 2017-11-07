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

/* Test that the application of a bad patch does not leave the target object in
   intermediate state.  I.e. if a patch fails, the target object should be
   unchanged.
 */
static bool patch_test(const char* docstr, const char* patchstr)
{
  json_value doc=json_decode(docstr);
  json_value orig = doc;
  json_array patch=json_decode(patchstr).as_array();
  bool had_exception = true;
  bool patch_ok;

  // apply the patch, ignore errors
  try
  {
    patch_ok = apply_patch(doc, patch);
    had_exception = false;
  }
  catch (std::exception& e)
  {
    std::cout << "apply patch exception: " << e.what() << "\n";
  }

  if (!had_exception && patch_ok)
    throw std::runtime_error("test was expected to fail");

  bool equal = (doc == orig);

  if (!equal)
  {
    std::cout << "before: '" << orig << "'\n"
              << "after : '" << doc << "'\n";
  }
  return equal;
}


//----------------------------------------------------------------------

TEST_CASE( "rollback_due_to_test" )
{
  const char* doc =  " { \"foo\": [\"bar\", \"baz\"] } ";

  const char* patch = " \
 [                                                                     \
    { \"op\": \"copy\", \"from\": \"/foo\", \"path\": \"/bar\" },      \
    { \"op\": \"copy\", \"from\": \"/foo\", \"path\": \"/bar2\" },     \
    { \"op\": \"replace\", \"path\": \"/foo/0\", \"value\": \"xxx\" }, \
    { \"op\": \"test\", \"path\": \"/foo/0\", \"value\": \"bar\" }     \
]                                                                      \
";

  REQUIRE(
    patch_test( doc, patch )
    );
}
//----------------------------------------------------------------------

TEST_CASE( "rollback_due_to_bad_patch" )
{
  const char* doc =  " { \"foo\": [\"bar\", \"baz\"] } ";

  const char* patch = " \
 [                                                                     \
    { \"op\": \"copy\", \"from\": \"/foo\", \"path\": \"/bar\" },      \
    { \"op\": \"copy\", \"from\": \"/foo\", \"path\": \"/bar2\" },     \
    { \"op\": \"replace\", \"path\": \"/faa/01\", \"value\": \"yy\" }, \
    { \"op\": \"test\", \"path\": \"/foo/0\", \"value\": \"bar\" }     \
]                                                                      \
";

  REQUIRE(
    patch_test( doc, patch )
    );
}
//----------------------------------------------------------------------

TEST_CASE( "rollback_full_doc" )
{
  const char* doc =  " { \"foo\": [\"bar\", \"baz\"] } ";

  const char* patch = " \
 [                                                                     \
    { \"op\": \"remove\", \"from\": \"/foo\", \"path\": \"\" },        \
    { \"op\": \"replace\", \"path\": \"/faa/1\", \"value\": \"yy\" }, \
    { \"op\": \"test\", \"path\": \"/foo/0\", \"value\": \"bar\" }     \
]                                                                      \
";

  REQUIRE(
    patch_test( doc, patch )
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
