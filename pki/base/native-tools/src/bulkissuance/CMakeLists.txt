project(bulkissuance C)

set(BULKISSUANCE_PRIVATE_INCLUDE_DIRS
  ${CMAKE_BINARY_DIR}
  ${NSPR_INCLUDE_DIRS}
  ${NSS_INCLUDE_DIRS}
)

set(BULKISSUANCE_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
)

set(bulkissuance_SRCS
    bulkissuance.c
    getopt.c
)

include_directories(${BULKISSUANCE_PRIVATE_INCLUDE_DIRS})

add_executable(bulkissuance ${bulkissuance_SRCS})

target_link_libraries(bulkissuance ${BULKISSUANCE_LINK_LIBRARIES})

install(
    TARGETS bulkissuance
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

install(
    FILES
        bulkissuance.data
    DESTINATION
        ${LIB_INSTALL_DIR}/pki/native-tools/
)
