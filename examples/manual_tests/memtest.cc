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
  v.as<jalson::json_array>().push_back( "this is astring" );
  v.as<jalson::json_array>().push_back( jalson::json_object() );
  v.as<jalson::json_array>().push_back( v );
  v.as<jalson::json_array>().push_back( v );
  v.as<jalson::json_array>().push_back( v );
  v.as<jalson::json_array>().push_back( v );

  return v;
}



int test()
{
  jalson::json_value v = build_json();
  std::string enc = jalson::json_encode(v.as<jalson::json_array>()  );

  int count = 0;
  while (true)
  {

    {
      jalson::json_value v = build_json();
      jalson::json_encode(v.as<jalson::json_array>()  );
    }

    {
      jalson::json_value dest;
      jalson::json_decode(dest, enc.c_str());
    }
    {

      jalson::json_object ob;
      ob["1"] = jalson::json_value(1);
      ob["2"] = jalson::json_value(2);
      ob["3"] = jalson::json_value(3);
      ob["4"] = jalson::json_value(4);
      ob["ob"] = ob;
      jalson::json_array ar;
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

  jalson::json_value dest;
  jalson::json_decode(dest, str);
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
