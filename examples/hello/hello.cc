/* Basic example of use jalson */

#include <jalson/jalson.h>

#include <iostream>

int main(int, char**)
{
  // obtain details about the JSON implementation wrapped inside jalson

  jalson::vendor_details details;
  jalson::get_vendor_details(&details);

  std::cout << "JSON implementation: "
            << details.vendor << " "
            << details.major_version << "."
            << details.minor_version << "."
            << details.micro_version << "\n";

  // --- Build a JSON object ---

  jalson::json_value v = jalson::decode("[\"hello\", {}, 2015]");

  // --- Add some items programmatically ---

  // using methods of the stl container
  v.as_array().push_back("world");
  v.as_array().push_back(1);
  v.as_array().push_back(true);
  v.as_array().push_back( jalson::json_object() );
  v.as_array().push_back( jalson::json_array() );

  // using helper methods of json_value type
  v[1]["vendor"]  = details.vendor;
  v[1]["version"] = details.major_version;

  // Print
  std::cout << v << "\n";
  return 0;
}
