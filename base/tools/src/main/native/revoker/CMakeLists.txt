project(revoker C)

set(REVOKER_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(REVOKER_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(revoker_SRCS
    revoker.c
    getopt.c
)

include_directories(${REVOKER_PRIVATE_INCLUDE_DIRS})

add_executable(revoker ${revoker_SRCS})
add_dependencies(revoker p7tool)
target_link_libraries(revoker ${REVOKER_LINK_LIBRARIES})

install(
    TARGETS revoker
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
