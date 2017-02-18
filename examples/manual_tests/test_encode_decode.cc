#include <jalson/jalson.h>

#include <iostream>
#include <stdint.h>

#include <limits>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

jalson::json_value build_json()
{
  jalson::json_value v = jalson::json_value::make_array();
  v.as<jalson::json_array>().push_back( 1 );
  v.as<jalson::json_array>().push_back( 1.1 );
  v.as<jalson::json_array>().push_back( "this is a string" );
  v.as<jalson::json_array>().push_back( jalson::json_object() );
  v.as<jalson::json_array>().push_back( v );
  v.as<jalson::json_array>().push_back( v );
  v.as<jalson::json_array>().push_back( v );
  v.as<jalson::json_array>().push_back( v );

  jalson::json_object & obj = v.append_object();
  obj["one"] = v;
  obj["two"] = v;
  v.as<jalson::json_array>().push_back( v );

  return v;
}


int strlen_total  = 0;

jalson::json_value test()
{
  jalson::json_value v = build_json();
  std::string enc = jalson::json_encode(v.as<jalson::json_array>()  );
  std::cout << enc << "\n";

  int count = 0;
  jalson::json_value rv;

  while (count < 100)
  {
    // encode
    jalson::json_value v = build_json();
    jalson::json_encode(v.as<jalson::json_array>()  );

    // decode
    jalson::json_decode(rv, enc.c_str());

    std::string s =  jalson::json_encode( v );
    strlen_total += s.size();

    std::cout << "loop #" << count++ << "\n";
    usleep(10000);
  }

  return rv;
}

int main(int, char**)
{
  jalson::json_value v = test();
  std::string enc = jalson::json_encode(v.as<jalson::json_array>());
  std::cout << enc << "\n";
  std::cout << strlen_total << "\n";
  return 0;
}
