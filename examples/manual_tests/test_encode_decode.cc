#include "wampcc/json.h"

#include <iostream>
#include <stdint.h>

#include <limits>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

wampcc::json_value build_json()
{
  wampcc::json_value v = wampcc::json_value::make_array();
  v.as<wampcc::json_array>().push_back( 1 );
  v.as<wampcc::json_array>().push_back( 1.1 );
  v.as<wampcc::json_array>().push_back( "this is a string" );
  v.as<wampcc::json_array>().push_back( wampcc::json_object() );
  v.as<wampcc::json_array>().push_back( v );
  v.as<wampcc::json_array>().push_back( v );
  v.as<wampcc::json_array>().push_back( v );
  v.as<wampcc::json_array>().push_back( v );

  wampcc::json_object & obj = v.append_object();
  obj["one"] = v;
  obj["two"] = v;
  v.as<wampcc::json_array>().push_back( v );

  return v;
}


int strlen_total  = 0;

wampcc::json_value test()
{
  wampcc::json_value v = build_json();
  std::string enc = wampcc::json_encode(v.as<wampcc::json_array>()  );
  std::cout << enc << "\n";

  int count = 0;
  wampcc::json_value rv;

  while (count < 100)
  {
    // encode
    wampcc::json_value v = build_json();
    wampcc::json_encode(v.as<wampcc::json_array>()  );

    // decode
    wampcc::json_decode(rv, enc.c_str());

    std::string s =  wampcc::json_encode( v );
    strlen_total += s.size();

    std::cout << "loop #" << count++ << "\n";
    usleep(10000);
  }

  return rv;
}

int main(int, char**)
{
  wampcc::json_value v = test();
  std::string enc = wampcc::json_encode(v.as<wampcc::json_array>());
  std::cout << enc << "\n";
  std::cout << strlen_total << "\n";
  return 0;
}
