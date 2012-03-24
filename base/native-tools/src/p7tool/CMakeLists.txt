project(p7tool C)

set(P7TOOL_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(P7TOOL_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(p7tool_SRCS
    secerror.c
    secpwd.c
    secutil.c
    pppolicy.c
    p7tool.c
)

include_directories(${P7TOOL_PRIVATE_INCLUDE_DIRS})

add_executable(p7tool ${p7tool_SRCS})

target_link_libraries(p7tool ${P7TOOL_LINK_LIBRARIES})

install(
    TARGETS p7tool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
