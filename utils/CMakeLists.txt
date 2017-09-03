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

list(APPEND EXTRA_LIBS uv)

if(BUILD_UTILS)

  add_executable(admin "${PROJECT_SOURCE_DIR}/utils/admin.cc")
  set_property(TARGET admin PROPERTY CXX_STANDARD 11)
  set_property(TARGET admin PROPERTY CXX_STANDARD_REQUIRED ON)
  target_link_libraries (admin  ${EXTRA_LIBS})

  ##
  ## Install targets
  ##
  install (TARGETS admin DESTINATION "${INSTALL_BIN_DIR}")

endif() # BUILD_UTILS
