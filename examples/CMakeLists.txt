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

# Helper macro for example compilation
macro(Compile_Example example source_path)
  add_executable(${example} "${PROJECT_SOURCE_DIR}/examples/${source_path}/${example}.cc")
  set_property(TARGET ${example} PROPERTY CXX_STANDARD 11)
  set_property(TARGET ${example} PROPERTY CXX_STANDARD_REQUIRED ON)
  target_link_libraries (${example}  ${EXTRA_LIBS})

  if (WIN32)
    set_target_properties(${example} PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
  endif()
endmacro()


if(BUILD_EXAMPLES)

# Basic
  Compile_Example(basic_embedded_router basic)
  Compile_Example(basic_caller basic)
  Compile_Example(basic_callee basic)
  Compile_Example(basic_callee_ssl basic)
  Compile_Example(demo_embedded_router_ssl basic)
  Compile_Example(demo_embedded_router basic)
  Compile_Example(basic_server basic)
# Authentication
  Compile_Example(basic_authentication_provider authentication)
# Authorization
  Compile_Example(basic_authorization_provider authorization)
# Message server
  Compile_Example(message_server message_server)
  Compile_Example(message_subscriber message_server)
# SSL socket
  Compile_Example(ssl_server ssl_socket)
  Compile_Example(ssl_client ssl_socket)
# WAMP router
  Compile_Example(router wamp_router)

endif() # BUILD_EXAMPLES
