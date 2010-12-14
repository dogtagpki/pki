project(tpsclient CXX)

set(TPS_PRIVATE_INCLUDE_DIRS
    ${TPS_PUBLIC_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
)

set(TPS_EXECUTABLE
    tpsclient
    CACHE INTERNAL "tpsclient executable"
)

set(TPS_LINK_LIBRARIES
    ${TPS_SHARED_LIBRARY}
    ${NSPR_LIBRARIES}
    ${NSS_LIBRARIES}
)

set(tpsclient_SRCS
    RA_Client.cpp
    RA_Conn.cpp
    RA_Token.cpp
)

include_directories(${TPS_PRIVATE_INCLUDE_DIRS})

add_executable(${TPS_EXECUTABLE} ${tpsclient_SRCS})
target_link_libraries(${TPS_EXECUTABLE} ${TPS_LINK_LIBRARIES})

install(
    TARGETS
        ${TPS_EXECUTABLE}
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

install(
    FILES
        enroll.tps
        format.tps
        reset_pin.tps
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tps/samples
)
