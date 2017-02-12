#include "test_common.h"


using namespace wampcc;
using namespace std;


void test_fast_close(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  assert(callback_status == e_close_callback_with_sp);
}


void test_fast_close_duplicate(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

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
  assert(callback_status == e_close_callback_with_sp);
}



void test_fast_close_on_ev(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

    the_kernel->get_event_loop()->dispatch([session](){
        session->fast_close();
        assert(session->is_open() == false);
        assert(session->is_closed() == true);
      });

    session->closed_future().wait();
  }

  // ensure callback was invoked
  assert(callback_status == e_close_callback_with_sp);
}


void test_fast_close_after_normal_close(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

    session->close();
    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  assert(callback_status == e_close_callback_with_sp);
}


void test_fast_close_after_normal_close_and_wait(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

    session->close();
    session->closed_future().wait();
    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
  }

  // ensure callback was invoked
  assert(callback_status == e_close_callback_with_sp);
}


void normal_close_and_wait_after_close(int port)
{
  cout << "---------- "<< __FUNCTION__ <<" ----------\n";

  callback_status = e_callback_not_invoked;

  {
    unique_ptr<kernel> the_kernel(new kernel({}, logger::nolog()));
    auto session = establish_session(the_kernel, port);
    if (!session) return;

    session->fast_close();
    assert(session->is_open() == false);
    assert(session->is_closed() == true);
    session->close();
    session->closed_future().wait();
  }

  // ensure callback was invoked
  assert(callback_status == e_close_callback_with_sp);
}

int main(int argc, char** argv)
{
  try
  {
    int starting_port_number = 25000;

    if (argc>1)
      starting_port_number = atoi(argv[1]);

    auto all_tests = [](int port)
      {
        test_fast_close(port);
        test_fast_close_duplicate(port);
        test_fast_close_after_normal_close(port);
        test_fast_close_after_normal_close_and_wait(port);
        normal_close_and_wait_after_close(port);
        test_fast_close_on_ev(port);
      };

    // one-off test
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port);
    }

    // share a common internal_server
    for (int i = 0; i < 50; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port);

      for (int j=0; j < 100; j++)
        all_tests(port);
    }

    // use one internal_server per test
    for (int i = 0; i < 1000; i++)
    {
      internal_server iserver;
      int port = iserver.start(starting_port_number++);
      all_tests(port);
    }

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}
