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
  v.as<jalson::JSONArray>().push_back( "this is astring" );
  v.as<jalson::JSONArray>().push_back( jalson::JSONObject() );
  v.as<jalson::JSONArray>().push_back( v );
  v.as<jalson::JSONArray>().push_back( v );
  v.as<jalson::JSONArray>().push_back( v );
  v.as<jalson::JSONArray>().push_back( v );

  return v;
}



int test()
{
  jalson::JSONValue v = build_json();
  char * enc = jalson::encode(v.as<jalson::JSONArray>()  );

  int count = 0;
  while (true)
  {

    {
      jalson::JSONValue v = build_json();
      char * tmp = jalson::encode(v.as<jalson::JSONArray>()  );
      free(tmp);
    }

    {
      jalson::JSONValue dest;
      jalson::decode(dest, enc);
    }
    {

      jalson::JSONObject ob;
      ob["1"] = jalson::JSONValue(1);
      ob["2"] = jalson::JSONValue(2);
      ob["3"] = jalson::JSONValue(3);
      ob["4"] = jalson::JSONValue(4);
      ob["ob"] = ob;
      jalson::JSONArray ar;
      ar.push_back( ob );
      ar.push_back( ar );
    }

    std::cout << "loop #" << count++ << "\n";
    usleep(1000);
  }
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


  jalson::JSONValue dest;
  jalson::decode(dest, str);


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
