
#include <json_pointer.cc>
#include "testcase.h"

#include <fstream>
#include <vector>

using namespace jalson;


#ifndef JALSONDIR
#error JALSONDIR must be defined during compilation
#endif


std::string slurp(const std::string &filename)
{
  std::cout << "reading '" << filename << "'\n";
  std::ifstream ifs(filename.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

  if (ifs)
  {
    std::ifstream::pos_type filesize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::vector<char> bytes(filesize);
    ifs.read(&bytes[0], filesize);

    return std::string(&bytes[0], filesize);
  }
  else
  {
    std::cout << "cannot open file\n";
    exit(1);
  }
}

bool run_test(json_object& tc, int testid)
{
  std::cout << "--------------------------------------------------\n";
  std::cout << "testid: " << testid << "\n";
  std::cout << "test  : " << tc["comment"] << "\n";


  enum
  {
    eSuccess = 0,
    ePrepFailed,
    ePatchFailed,
    eDiffFailed
  } result = eSuccess;
  const  char* names []={"Success","PrepFailed","PatchFailed","DiffFailed"};


  json_value doc;
  json_value orig;
  json_array patch;
  json_value disabled;
  bool expect_fail = false;
  try
  {
    doc= tc["doc"];
    orig = doc;
    patch = tc["patch"].as_array();
    disabled = tc["disabled"];


    std::cout << "start : '" << orig << "'\n"
              << "patch : '" << patch << "'\n";

    if (disabled.is_true())
    {
      std::cout << "disabled: true\n";
      return true;
    }
    expect_fail = (tc.find("error") != tc.end());
  }
  catch(pointer_fail&e)
  {
    std::cout << "patch exception:" << e.what() << ", index " << e.path_index << "\n";
    result = ePatchFailed;
  }
  catch(std::exception&e)
  {
    std::cout << "prep exception:" << e.what() << "\n";
    result = ePrepFailed;
  }

  if (result == eSuccess)
  {
    try
    {
      bool patch_ok = apply_patch(doc, patch);
      if (!patch_ok) result = ePatchFailed;
    }
    catch(pointer_fail&e)
    {
      std::cout << "caught: pointer_fail" << e.what() << ", index " << e.path_index << "\n";
      result = ePatchFailed;
    }
    catch(std::exception&e)
    {
      std::cout << "caught: std::exception, " << e.what() << "\n";
      result = ePatchFailed;
    }
  }
  std::cout << "after : '" << doc << "'\n";

  if (result == eSuccess)
  {
    json_object::iterator expect= tc.find("expected");

    if (expect != tc.end())
    {

      std::cout << "expect : '" << expect->second << "'\n";

      if (doc != expect->second)
      {
        std::cout << "result: not equal\n";
        result = eDiffFailed;
      }
      else
      {
        std::cout << "result: equal\n";
      }
    }
  }

  if (expect_fail)
  {
    if (result == eSuccess)
    {
      std::cout << "result: FAIL - expected fail but had success\n";
      return false;
    }
    else
    {
      bool doc_restored = (doc == orig);
      if (doc_restored)
      {
        std::cout << "result: PASS - expected fail and had "<< names[result] << ", and orig state restored\n";
        return true;
      }
      else
      {
        std::cout << "result: FAIL - expected and got fail "<< names[result] << ", but doc not in orig state\n";
        return false;
      }
    }
  }
  else
  {
    std::cout << "result: " << ((result == eSuccess)?"PASS":"FAIL")<< " - "<< names[result] <<"\n";
    return (result == eSuccess);
  }
}

void load_tests(json_array& all, const char* filename)
{
  std::string tests = slurp( filename );
  json_value doc = jalson::decode(tests.c_str());
  json_array& loaded_tests = doc.as_array();
  all.insert(all.end(), loaded_tests.begin(), loaded_tests.end());
}

int main(int argc, char * argv [])
{
  int usertest = (argc>1)? atoi(argv[1]) : -1;

  json_array json_tests;
  load_tests(json_tests, JALSONDIR "/tests/tests.json");
  load_tests(json_tests, JALSONDIR "/tests/extra.json");

  // std::string tests = slurp( JALSONDIR "/tests/tests.json" );

  // json_value doc = jalson::decode(tests.c_str());

  // json_array& json_tests = doc.as_array();

  int testid = 0;
  int failed = 0;
  int run = 0;
  for (json_array::iterator it = json_tests.begin();
       it != json_tests.end(); ++it, ++testid)
  {
    if (usertest == -1 || usertest == testid)
    {
      run++;
      if (run_test(it->as_object(), testid) == false) failed++;
    }
  }

  std::cout << "--------------------------------------------------\n";
  std::cout << "JSON PATCH SUMMARY\n";
  std::cout << "--------------------------------------------------\n";
  std::cout << "TESTS : " << run << "\n";
  std::cout << "FAILS : " << failed << "\n";


  return (failed>0)? 1: 0;
}
