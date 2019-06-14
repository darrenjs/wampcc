/*
 * Copyright (c) 2017 Darren Smith
 *
 * wampcc is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "wampcc/wampcc.h"

#include <memory>
#include <iostream>


int main(int argc, char** argv)
{
  /*
    Example of inspecting wampcc to discover the version of libuv it was
    compiled with.  The version used at runtime can also be obtained, and these
    can optionally be compared to detect any discrepancy.
   */

  int cmajor, cminor;
  wampcc::libuv_version_wampcc_compiletime(cmajor, cminor);
  std::cout << "wampcc was compiled with libuv version " << cmajor << "." << cminor << std::endl;

  int lmajor, lminor;
  wampcc::libuv_version_runtime(lmajor, lminor);
  std::cout << "this binary is linked to libuv version " << lmajor << "." << lminor << std::endl;

  if (lmajor != cmajor)
    std::cout << "warning, appears to be major version mismatch!" << std::endl;
}
