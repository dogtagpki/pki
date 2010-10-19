project(sslget C)

set(SSLGET_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(SSLGET_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(sslget_SRCS
    sslget.c
    getopt.c
)

include_directories(${SSLGET_PRIVATE_INCLUDE_DIRS})

add_executable(sslget ${sslget_SRCS})

target_link_libraries(sslget ${SSLGET_LINK_LIBRARIES})

install(
    TARGETS sslget
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
