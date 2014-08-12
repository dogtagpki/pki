project(tps_library CXX)

set(TPS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(tus)

set(TPS_PUBLIC_INCLUDE_DIRS
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${TPS_INCLUDE_DIR}
  CACHE INTERNAL "tps public include directories"
)

set(TPS_PRIVATE_INCLUDE_DIRS
  ${TPS_PUBLIC_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
  ${NSS_INCLUDE_DIRS}
  ${NSPR_INCLUDE_DIRS}
  ${APR_INCLUDE_DIRS}
  ${SVRCORE_INCLUDE_DIRS}
  ${LDAP_INCLUDE_DIRS}
)

set(TPS_SHARED_LIBRARY
  tps_library
  CACHE INTERNAL "tps shared library"
)

set(TPS_LINK_LIBRARIES
  ${NSPR_LIBRARIES}
  ${NSS_LIBRARIES}
  ${APR_LIBRARIES}
  ${SVRCORE_LIBRARIES}
  ${LDAP_LIBRARIES}
  ${TOKENDB_SHARED_LIBRARY}
)

set(tps_library_SRCS
    main/Buffer.cpp
    main/NameValueSet.cpp
    main/ConfigStore.cpp
    main/Util.cpp
    main/RA_Msg.cpp
    main/RA_pblock.cpp
    main/RA_Session.cpp
    main/RA_Context.cpp
    main/Login.cpp
    main/SecureId.cpp
    main/Memory.cpp
    main/AuthenticationEntry.cpp
    main/AuthParams.cpp
    main/Authentication.cpp
    main/AttributeSpec.cpp
    main/ObjectSpec.cpp
    main/PKCS11Obj.cpp
    main/LogFile.cpp
    main/RollingLogFile.cpp
    httpClient/httpClient.cpp
    httpClient/Cache.cpp
    httpClient/engine.cpp
    httpClient/http.cpp
    httpClient/response.cpp
    httpClient/request.cpp
    httpClient/nscperror.cpp
    cms/HttpConnection.cpp
    cms/ConnectionInfo.cpp
    cms/CertEnroll.cpp
    apdu/APDU.cpp
    apdu/Unblock_Pin_APDU.cpp
    apdu/Create_Object_APDU.cpp
    apdu/Set_Pin_APDU.cpp
    apdu/Set_IssuerInfo_APDU.cpp
    apdu/Get_IssuerInfo_APDU.cpp
    apdu/Create_Pin_APDU.cpp
    apdu/List_Pins_APDU.cpp
    apdu/Initialize_Update_APDU.cpp
    apdu/Get_Version_APDU.cpp
    apdu/Get_Status_APDU.cpp
    apdu/Get_Data_APDU.cpp
    apdu/External_Authenticate_APDU.cpp
    apdu/Generate_Key_APDU.cpp
    apdu/Generate_Key_ECC_APDU.cpp
    apdu/Read_Buffer_APDU.cpp
    apdu/Read_Object_APDU.cpp
    apdu/Write_Object_APDU.cpp
    apdu/Put_Key_APDU.cpp
    apdu/Select_APDU.cpp
    apdu/Delete_File_APDU.cpp
    apdu/Install_Applet_APDU.cpp
    apdu/Format_Muscle_Applet_APDU.cpp
    apdu/Load_File_APDU.cpp
    apdu/Install_Load_APDU.cpp
    apdu/Lifecycle_APDU.cpp
    apdu/List_Objects_APDU.cpp
    apdu/Import_Key_APDU.cpp
    apdu/Import_Key_Enc_APDU.cpp
    apdu/APDU_Response.cpp
    msg/RA_Begin_Op_Msg.cpp
    msg/RA_End_Op_Msg.cpp
    msg/RA_Login_Request_Msg.cpp
    msg/RA_Login_Response_Msg.cpp
    msg/RA_SecureId_Request_Msg.cpp
    msg/RA_SecureId_Response_Msg.cpp
    msg/RA_ASQ_Request_Msg.cpp
    msg/RA_ASQ_Response_Msg.cpp
    msg/RA_New_Pin_Request_Msg.cpp
    msg/RA_New_Pin_Response_Msg.cpp
    msg/RA_Token_PDU_Request_Msg.cpp
    msg/RA_Token_PDU_Response_Msg.cpp
    msg/RA_Status_Update_Request_Msg.cpp
    msg/RA_Status_Update_Response_Msg.cpp
    msg/RA_Extended_Login_Request_Msg.cpp
    msg/RA_Extended_Login_Response_Msg.cpp
    channel/Channel.cpp
    channel/Secure_Channel.cpp
    engine/RA.cpp
    processor/RA_Processor.cpp
    processor/RA_Enroll_Processor.cpp
    processor/RA_Pin_Reset_Processor.cpp
    processor/RA_Renew_Processor.cpp
    processor/RA_Unblock_Processor.cpp
    processor/RA_Format_Processor.cpp
    selftests/SelfTest.cpp
    selftests/TPSPresence.cpp
    selftests/TPSSystemCertsVerification.cpp
    selftests/TPSValidity.cpp
)

include_directories(${TPS_PRIVATE_INCLUDE_DIRS})

add_library(${TPS_SHARED_LIBRARY} SHARED ${tps_library_SRCS})
target_link_libraries(${TPS_SHARED_LIBRARY} ${TPS_LINK_LIBRARIES})

set_target_properties(
    ${TPS_SHARED_LIBRARY}
    PROPERTIES
        OUTPUT_NAME
            tps
)

install(
    TARGETS
        ${TPS_SHARED_LIBRARY}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}/tps
)

add_subdirectory(authentication)
add_subdirectory(modules)

