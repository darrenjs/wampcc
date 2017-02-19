#include "wampcc/json.h"

#include <iostream>
#include <stdint.h>

#include <limits>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

using namespace wampcc;

json_value build_json()
{
  json_value v = json_value::make_array();
  v.as<json_array>().push_back( 1 );
  v.as<json_array>().push_back( 1.1 );
  v.as<json_array>().push_back( "this is astring" );
  v.as<json_array>().push_back( json_object() );
  v.as<json_array>().push_back( v );
  v.as<json_array>().push_back( v );
  v.as<json_array>().push_back( v );
  v.as<json_array>().push_back( v );

  return v;
}



int test()
{
  json_value v = build_json();
  std::string enc = json_encode(v.as<json_array>()  );

  int count = 0;
  while (true)
  {

    {
      json_value v = build_json();
      json_encode(v.as<json_array>()  );
    }

    {
      json_value dest;
      json_decode(dest, enc.c_str());
    }
    {

      json_object ob;
      ob["1"] = json_value(1);
      ob["2"] = json_value(2);
      ob["3"] = json_value(3);
      ob["4"] = json_value(4);
      ob["ob"] = ob;
      json_array ar;
      ar.push_back( ob );
      ar.push_back( ar );
    }

    std::cout << "loop #" << count++ << "\n";
    usleep(1000);
  }
  return 0;
}



#define THIS   " @" << this << " "

struct MyT
{
  MyT()
    : m_i(-1)
  {
    std::cout << THIS << "MyT::MyT() " << m_i << "\n";
  }
  MyT(int i)
    : m_i(i)
  {
    std::cout << THIS << "MyT::MyT(" << m_i << ")" <<"\n";
  }

  MyT(const MyT& s)
    : m_i(s.m_i)
  {
    std::cout << THIS << "MyT::MyT(MyT s=" << s.m_i<<") from" << &s << "\n";
  }

  MyT& operator=(const MyT& s)
  {
    this->m_i = s.m_i;
    std::cout << THIS << "MyT::operator=(MyT s="<< s.m_i << ") from " << &s << "\n";
    return *this;
  }
  ~MyT()
  {
    std::cout << THIS << "MyT::~MyT " << m_i <<  "\n";
  }

  int m_i;
};


void parse_invalid()
{
  const char* str = " [1,2,,[}]";

  json_value dest;
  json_decode(dest, str);
}

int main(int, char**)
{

  // std::vector<MyT> col;
  // col.reserve(2);
  // col.push_back( MyT(0) );
  // col.push_back( MyT(1) );


  std::map<int, MyT> m;
  m[0]=MyT(0);
  m[1]=MyT(1);


//  parse_invalid();

  test();

  return 0;
}
