project(p12tool C)

set(P12TOOL_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(P12TOOL_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(p12tool_SRCS
    basicutil.c
    pppolicy.c
    secutil.c
    secpwd.c
    moreoids.c
    p12tool.c
)

include_directories(${P12TOOL_PRIVATE_INCLUDE_DIRS})

add_executable(p12tool ${p12tool_SRCS})
add_dependencies(p12tool pki-common-jar)
target_link_libraries(p12tool ${P12TOOL_LINK_LIBRARIES})

install(
    TARGETS p12tool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)
