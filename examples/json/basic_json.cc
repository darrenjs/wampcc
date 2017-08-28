/* Basic example of use jalson */

#include <wampcc/json.h>

#include <iostream>

int main(int, char**)
{
  // obtain details about the JSON implementation wrapped inside wampcc

  wampcc::vendor_details details;
  wampcc::get_vendor_details(&details);

  std::cout << "JSON implementation: "
            << details.vendor << " "
            << details.major_version << "."
            << details.minor_version << "."
            << details.micro_version << "\n";

  // --- Build a JSON object ---

  wampcc::json_value v = wampcc::json_decode("[\"hello\", {}, 2015]");

  // --- Add some items programmatically ---

  // using methods of the stl container
  v.as_array().push_back("world");
  v.as_array().push_back(1);
  v.as_array().push_back(true);
  v.as_array().push_back( wampcc::json_object() );
  v.as_array().push_back( wampcc::json_array() );

  // using helper methods of json_value type
  v[1]["vendor"]  = details.vendor;
  v[1]["version"] = details.major_version;

  // Print
  std::cout << v << "\n";
  return 0;
}
