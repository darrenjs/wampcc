if(BUILD_SHARED_LIBS)
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_shared wampcc_json_shared)
else()
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_static wampcc_json_static)
endif()

if (WIN32)
  list(APPEND EXTRA_LIBS libuv ssleay32 libeay32)
  # libuv library dependencies
  list(APPEND EXTRA_LIBS advapi32 iphlpapi psapi shell32 user32 userenv ws2_32)
else()
  list(APPEND EXTRA_LIBS uv crypto ssl pthread)
endif()

list(APPEND EXTRA_LIBS jansson)

if(BUILD_TESTS)

  add_executable(test_misc
    "${PROJECT_SOURCE_DIR}/tests/test_misc.cc"
    "${PROJECT_SOURCE_DIR}/tests/test_common.h" )
  set_property(TARGET test_misc PROPERTY CXX_STANDARD 11)
  set_property(TARGET test_misc PROPERTY CXX_STANDARD_REQUIRED ON)
  target_link_libraries(test_misc ${EXTRA_LIBS})

  if (WIN32)
    set_target_properties(test_misc PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
  endif()


##
## Add more test build rules here
##

endif() # BUILD_TESTS
