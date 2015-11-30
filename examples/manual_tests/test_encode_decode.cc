#include <jalson/jalson.h>

#include <iostream>
#include <stdint.h>

#include <limits>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

jalson::JSONValue build_json()
{
  jalson::JSONValue v = jalson::JSONValue::make_array();
  v.as<jalson::JSONArray>().push_back( 1 );
  v.as<jalson::JSONArray>().push_back( 1.1 );
  v.as<jalson::JSONArray>().push_back( "this is a string" );
  v.as<jalson::JSONArray>().push_back( jalson::JSONObject() );
  v.as<jalson::JSONArray>().push_back( v );
  v.as<jalson::JSONArray>().push_back( v );
  v.as<jalson::JSONArray>().push_back( v );
  v.as<jalson::JSONArray>().push_back( v );

  jalson::JSONObject & obj = jalson::append_object(v.as_array());
  obj["one"] = v;
  obj["two"] = v;
  v.as<jalson::JSONArray>().push_back( v );

  return v;
}


int strlen_total  = 0;

jalson::JSONValue test()
{
  jalson::JSONValue v = build_json();
  char * enc = jalson::encode(v.as<jalson::JSONArray>()  );
  std::cout << enc << "\n";

  int count = 0;
  jalson::JSONValue rv;

  while (count < 1000000)
  {
    // encode
    jalson::JSONValue v = build_json();
    char * tmp = jalson::encode(v.as<jalson::JSONArray>()  );

    // decode
    jalson::decode(rv, enc);


    free(tmp);

    // TODO: also call the tostring
    std::string s =  jalson::to_string( v );
    strlen_total += s.size();

    std::cout << "loop #" << count++ << "\n";
    usleep(10000);
  }

  return rv;
}

int main(int, char**)
{
  jalson::JSONValue v = test();
  char * enc = jalson::encode(v.as<jalson::JSONArray>());
  std::cout << enc << "\n";
  free(enc);
  std::cout << strlen_total << "\n";
  return 0;
}
