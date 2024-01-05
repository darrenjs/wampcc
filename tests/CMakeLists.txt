if(BUILD_SHARED_LIBS)
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_shared wampcc_json_shared)
else()
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_static wampcc_json_static)
endif()

list(APPEND EXTRA_LIBS ${LIBUV_LIBRARIES} ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})

if(BUILD_TESTS)

  # Helper macro for test compilation
  macro(Compile_Test TEST_NAME)
    add_executable(${TEST_NAME}
        "${PROJECT_SOURCE_DIR}/tests/wampcc/${TEST_NAME}.cc"
        "${PROJECT_SOURCE_DIR}/tests/wampcc/test_common.h" )
    target_link_libraries(${TEST_NAME} ${EXTRA_LIBS})
    target_include_directories(${TEST_NAME} PRIVATE "${PROJECT_SOURCE_DIR}")
    if (WIN32)
      set_target_properties(${TEST_NAME} PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
    endif()
  endmacro()

  Compile_Test(test_basic_codecs)
  Compile_Test(test_connect_timeout)
  Compile_Test(test_early_wamp_session_destructor)
  Compile_Test(test_evthread_wamp_session_destructor)
  Compile_Test(test_late_dealer_destructor)
  Compile_Test(test_late_wamp_session_destructor)
  Compile_Test(test_misc)
  Compile_Test(test_register_unregister)
  Compile_Test(test_router_functions)
  Compile_Test(test_send_and_close)
  Compile_Test(test_tcp_socket)
  Compile_Test(test_tcp_socket_connect)
  Compile_Test(test_tcp_socket_connect_cb)
  Compile_Test(test_tcp_socket_listen)
  Compile_Test(test_tcp_socket_passive_disconnect)
  Compile_Test(test_wamp_rpc)
  Compile_Test(test_wamp_session_fast_close)

##
## Add more test build rules here
##

endif() # BUILD_TESTS
