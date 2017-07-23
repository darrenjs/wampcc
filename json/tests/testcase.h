/*
 * Copyright (c) 2015 Darren Smith <jalson@darrenjs.net>
 *
 * Jalson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

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
  virtual ~testcasebase(){}
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

int autotest_runall()
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
  return (count_fail != 0);
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
  testcase__ ## X mytest_ ## X;                        \
  int X ()


