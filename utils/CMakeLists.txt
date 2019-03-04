if(BUILD_SHARED_LIBS)
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_shared wampcc_json_shared)
else()
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_static wampcc_json_static)
endif()

list(APPEND EXTRA_LIBS ${LIBUV_LIBRARIES} ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})

if(BUILD_UTILS)

  add_executable(admin "${PROJECT_SOURCE_DIR}/utils/admin.cc")
  set_property(TARGET admin PROPERTY CXX_STANDARD 11)
  set_property(TARGET admin PROPERTY CXX_STANDARD_REQUIRED ON)
  target_link_libraries (admin  ${EXTRA_LIBS})

  ##
  ## Install targets
  ##
  install (TARGETS admin DESTINATION "${INSTALL_BIN_DIR}" COMPONENT util)

endif() # BUILD_UTILS
