/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"
#include "mini_test.h"

using namespace wampcc;
using namespace std;

/* some of below tests are time consuming, so keep loops low */

int global_port;
int global_loops = 50;

void test_fast_close(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session)
      return;

    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  REQUIRE(callback_status == callback_status_t::close_with_sp);
}

TEST_CASE("test_fast_close")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_fast_close(port);
}

TEST_CASE("test_fast_close_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_fast_close(port);
}

void test_fast_close_duplicate(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session)
      return;

    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
    session->fast_close();
    session->fast_close();
    session->fast_close();
    session->fast_close();
    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  REQUIRE(callback_status == callback_status_t::close_with_sp);
}

TEST_CASE("test_fast_close_duplicate")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_fast_close_duplicate(port);
}

TEST_CASE("test_fast_close_duplicate_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_fast_close_duplicate(port);
}

void test_fast_close_on_ev(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session)
      return;

    the_kernel->get_event_loop()->dispatch([session]() {
      session->fast_close();
      assert(session->is_open() == false);
      assert(session->is_closed() == true);
    });

    session->closed_future().wait();
  }

  // ensure callback was invoked
  assert(callback_status == callback_status_t::close_with_sp);
}

TEST_CASE("test_fast_close_on_ev")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_fast_close_on_ev(port);
}

TEST_CASE("test_fast_close_on_ev_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_fast_close_on_ev(port);
}

void test_fast_close_after_normal_close(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session)
      return;

    session->close();
    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  REQUIRE(callback_status == callback_status_t::close_with_sp);
}

TEST_CASE("test_fast_close_after_normal_close")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_fast_close_after_normal_close(port);
}

TEST_CASE("test_fast_close_after_normal_close_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_fast_close_after_normal_close(port);
}

void test_fast_close_after_normal_close_and_wait(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session)
      return;

    session->close();
    session->closed_future().wait();
    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  assert(callback_status == callback_status_t::close_with_sp);
}

TEST_CASE("test_fast_close_after_normal_close_and_wait")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  test_fast_close_after_normal_close_and_wait(port);
}

TEST_CASE("test_fast_close_after_normal_close_and_wait_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    test_fast_close_after_normal_close_and_wait(port);
}

void normal_close_and_wait_after_close(int port)
{
  TSTART();

  callback_status = callback_status_t::not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session)
      return;

    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
    session->close();
    session->closed_future().wait();
  }

  // ensure callback was invoked
  assert(callback_status == callback_status_t::close_with_sp);
}

TEST_CASE("normal_close_and_wait_after_close")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  normal_close_and_wait_after_close(port);
}

TEST_CASE("normal_close_and_wait_after_close_bulk")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  for (int i = 0; i < global_loops; i++)
    normal_close_and_wait_after_close(port);
}

auto all_tests = [](int port) {
  test_fast_close(port);
  test_fast_close_duplicate(port);
  test_fast_close_after_normal_close(port);
  test_fast_close_after_normal_close_and_wait(port);
  normal_close_and_wait_after_close(port);
  test_fast_close_on_ev(port);
};

TEST_CASE("all_tests")
{
  internal_server iserver;
  int port = iserver.start(global_port++);
  all_tests(port);
}

TEST_CASE("all_tests_bulk")
{

  {
    /* share a server */
    internal_server iserver;
    int port = iserver.start(global_port++);
    for (int i = 0; i < std::min(2, global_loops / 5); ++i)
      all_tests(port);
  }

  {
    // use one internal_server per test
    for (int i = 0; i < std::min(2, global_loops / 5); i++) {
      internal_server iserver;
      int port = iserver.start(global_port++);
      all_tests(port);
    }
  }
}

int main(int argc, char** argv)
{
  try {
    global_port = 28000;

    if (argc > 1)
      global_port = atoi(argv[1]);

    int result = minitest::run(argc, argv);

    return (result < 0xFF ? result : 0xFF);
  } catch (exception& e) {
    cout << e.what() << endl;
    return 1;
  }
}
