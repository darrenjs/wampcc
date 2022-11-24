if(BUILD_SHARED_LIBS)
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_shared wampcc_json_shared)
else()
  set(EXTRA_LIBS ${EXTRA_LIBS} wampcc_static wampcc_json_static)
endif()

# Needed because std::condition_variable::wait_for() on libstdc++
# uses pthreads.
if(CMAKE_HOST_UNIX)
  set(EXTRA_LIBS ${EXTRA_LIBS} Threads::Threads)
endif()

if(BUILD_UTILS)

  add_executable(admin "${PROJECT_SOURCE_DIR}/utils/admin.cc")
  target_link_libraries (admin ${EXTRA_LIBS})

  ##
  ## Install targets
  ##
  install (TARGETS admin DESTINATION "${INSTALL_BIN_DIR}" COMPONENT util)

endif() # BUILD_UTILS
