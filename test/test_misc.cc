/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "test_common.h"

#include "wampcc/utils.h"

using namespace wampcc;
using namespace std;

void test_rpc()
{
  string value = iso8601_utc_timestamp();

  assert(value.size() == 24);
  assert(isdigit(value[0]));
  assert(isdigit(value[1]));
  assert(isdigit(value[2]));
  assert(isdigit(value[3]));
  assert(value[4]=='-');
  assert(isdigit(value[5]));
  assert(isdigit(value[6]));
  assert(value[7]=='-');
  assert(isdigit(value[8]));
  assert(isdigit(value[9]));
  assert(value[10]=='T');
  assert(isdigit(value[11]));
  assert(isdigit(value[12]));
  assert(value[13]==':');
  assert(isdigit(value[14]));
  assert(isdigit(value[15]));
  assert(value[16]==':');
  assert(isdigit(value[17]));
  assert(isdigit(value[18]));
  assert(value[19]=='.');
  assert(isdigit(value[20]));
  assert(isdigit(value[21]));
  assert(isdigit(value[22]));
  assert(value[23]=='Z');
}

int main(int argc, char** argv)
{
  try
  {
    test_rpc();

    return 0;
  }
  catch (exception& e)
  {
    cout << e.what() << endl;
    return 1;
  }

}
