project(tps CXX)

# NOTE:  TPS utilizes internal libraries located under '%{_libdir}/tps'.
#
#        One method of resolving this issue is the use of RPATH as
#        described in 'http://www.cmake.org/Wiki/CMake_RPATH_handling'.
#
#        While Fedora allows the use of RPATH for this purpose as documented
#        in the section entitled 'Rpath_for_Internal_Libraries' in the URL
#        called 'http://fedoraproject.org/wiki/Packaging/Guidelines',
#        the RPM '%cmake' macro overrides use of RPATH on Fedora and RHEL.
#
#        To resolve this issue on Fedora and RHEL, one of the following
#        methods may be utilized:
#
#        (1) Uncomment the 'SET(CMAKE_SKIP_RPATH  FALSE)' line below, or
#        (2) Implement the files described in the section entitled
#            'Alternatives to Rpath' in the URL called
#            'http://fedoraproject.org/wiki/Packaging/Guidelines'.

# use, i.e. don't skip the full RPATH
# (overrides '%cmake' macro setting of true)
#SET(CMAKE_SKIP_RPATH  FALSE)

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE) 

# the RPATH to be used when installing
SET(CMAKE_INSTALL_RPATH "${LIB_INSTALL_DIR}/tps")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(TPS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/include)

set(TPS_PUBLIC_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${TPS_INCLUDE_DIR}
    CACHE INTERNAL "TPS public include directories"
)

set(TPS_PRIVATE_INCLUDE_DIRS
    ${TPS_PUBLIC_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}
    ${NSPR_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
    ${APR_INCLUDE_DIRS}
    ${LDAP_INCLUDE_DIRS}
)

set(tpsclient_SRCS
    src/main/Buffer.cpp
    src/main/NameValueSet.cpp
    src/main/Util.cpp
    src/main/RA_Msg.cpp
    src/main/Memory.cpp
    src/main/AuthParams.cpp
    src/apdu/APDU.cpp
    src/apdu/Unblock_Pin_APDU.cpp
    src/apdu/Create_Object_APDU.cpp
    src/apdu/Set_Pin_APDU.cpp
    src/apdu/Set_IssuerInfo_APDU.cpp
    src/apdu/Get_IssuerInfo_APDU.cpp
    src/apdu/Create_Pin_APDU.cpp
    src/apdu/List_Pins_APDU.cpp
    src/apdu/Initialize_Update_APDU.cpp
    src/apdu/Get_Version_APDU.cpp
    src/apdu/Get_Status_APDU.cpp
    src/apdu/Get_Data_APDU.cpp
    src/apdu/External_Authenticate_APDU.cpp
    src/apdu/Generate_Key_APDU.cpp
    src/apdu/Generate_Key_ECC_APDU.cpp
    src/apdu/Read_Buffer_APDU.cpp
    src/apdu/Read_Object_APDU.cpp
    src/apdu/Write_Object_APDU.cpp
    src/apdu/Put_Key_APDU.cpp
    src/apdu/Select_APDU.cpp
    src/apdu/Delete_File_APDU.cpp
    src/apdu/Install_Applet_APDU.cpp
    src/apdu/Format_Muscle_Applet_APDU.cpp
    src/apdu/Load_File_APDU.cpp
    src/apdu/Install_Load_APDU.cpp
    src/apdu/Lifecycle_APDU.cpp
    src/apdu/List_Objects_APDU.cpp
    src/apdu/Import_Key_APDU.cpp
    src/apdu/Import_Key_Enc_APDU.cpp
    src/apdu/APDU_Response.cpp
    src/apdu/Get_Lifecycle_APDU.cpp
    src/msg/RA_Begin_Op_Msg.cpp
    src/msg/RA_End_Op_Msg.cpp
    src/msg/RA_Login_Request_Msg.cpp
    src/msg/RA_Login_Response_Msg.cpp
    src/msg/RA_SecureId_Request_Msg.cpp
    src/msg/RA_SecureId_Response_Msg.cpp
    src/msg/RA_ASQ_Request_Msg.cpp
    src/msg/RA_ASQ_Response_Msg.cpp
    src/msg/RA_New_Pin_Request_Msg.cpp
    src/msg/RA_New_Pin_Response_Msg.cpp
    src/msg/RA_Token_PDU_Request_Msg.cpp
    src/msg/RA_Token_PDU_Response_Msg.cpp
    src/msg/RA_Status_Update_Request_Msg.cpp
    src/msg/RA_Status_Update_Response_Msg.cpp
    src/msg/RA_Extended_Login_Request_Msg.cpp
    src/msg/RA_Extended_Login_Response_Msg.cpp
    tools/raclient/RA_Client.cpp
    tools/raclient/RA_Conn.cpp
    tools/raclient/RA_Token.cpp
)

set(TPS_EXECUTABLE
    tpsclient
    CACHE INTERNAL "tpsclient executable"
)

set(TPS_LINK_LIBRARIES
    ${NSPR_LIBRARIES}
    ${NSS_LIBRARIES}
    ${APR_LIBRARIES}
    ${LDAP_LIBRARIES}
)

include_directories(${TPS_PRIVATE_INCLUDE_DIRS})

add_executable(${TPS_EXECUTABLE} ${tpsclient_SRCS})
target_link_libraries(${TPS_EXECUTABLE} ${TPS_LINK_LIBRARIES})

add_custom_target(tpsclient-man ALL
    COMMENT "Creating PKI server manuals")

add_custom_command(
    TARGET tpsclient-man POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory man/man1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/tpsclient.1.md -out man/man1/tpsclient.1
)

install(
    TARGETS
        ${TPS_EXECUTABLE}
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}/tps
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}/tps
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)
