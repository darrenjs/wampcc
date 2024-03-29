if(BUILD_SHARED_LIBS)
  set(EXTRA_LIBS wampcc_shared wampcc_json_shared)
else()
  set(EXTRA_LIBS wampcc_static wampcc_json_static)
endif()

# Needed because std::condition_variable::wait_for() on libstdc++
# uses pthreads.
if(CMAKE_HOST_UNIX)
  set(EXTRA_LIBS ${EXTRA_LIBS} Threads::Threads)
endif()

# Helper macro for example compilation
macro(Compile_Example example source_path)
  add_executable(${example} "${PROJECT_SOURCE_DIR}/examples/${source_path}/${example}.cc")
  target_link_libraries (${example}	PRIVATE ${EXTRA_LIBS})

  if (WIN32)
    set_target_properties(${example} PROPERTIES LINK_FLAGS "/NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:libcmtd.lib")
  endif()
endmacro()


if(BUILD_EXAMPLES)

# Basic
  Compile_Example(basic_embedded_router basic)
  Compile_Example(basic_caller basic)
  Compile_Example(basic_callee basic)
  Compile_Example(basic_subscriber basic)
  Compile_Example(basic_publisher basic)
  Compile_Example(basic_callee_ssl basic)
  Compile_Example(demo_embedded_router_ssl basic)
  Compile_Example(demo_embedded_router basic)
  Compile_Example(demo_client basic)
  Compile_Example(basic_server basic)
# Authentication
  Compile_Example(basic_authentication_provider authentication)
  Compile_Example(ticket_authentication_provider authentication)
  Compile_Example(ticket_caller authentication)
  Compile_Example(external_authentication_provider authentication)
# Authorization
  Compile_Example(basic_authorization_provider authorization)
# Disclose
  Compile_Example(disclose_authorization_provider authorization)
  Compile_Example(disclose_callee authorization)
  Compile_Example(disclose_caller authorization)
  Compile_Example(disclose_publisher authorization)
  Compile_Example(disclose_subscriber authorization)
# Message server
  Compile_Example(message_server message_server)
  Compile_Example(message_subscriber message_server)
# SSL socket
  Compile_Example(ssl_server ssl_socket)
  Compile_Example(ssl_client ssl_socket)
# WAMP router
  Compile_Example(router wamp_router)

endif() # BUILD_EXAMPLES
