project(java-tools-wrapper)

set(PKI_PRODUCT pki)
set(PKI_COMMANDS
    AtoB
    AuditVerify
    BtoA
    CMCEnroll
    CMCRequest
    CMCResponse
    CMCRevoke
    CRMFPopClient
    DRMTool
    ExtJoiner
    GenExtKeyUsage
    GenIssuerAltNameExt
    GenSubjectAltNameExt
    HttpClient
    OCSPClient
    PKCS10Client
    PKCS12Export
    PrettyPrintCert
    PrettyPrintCrl
    TokenInfo
)

foreach(PKI_COMMAND ${PKI_COMMANDS})
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pki_java_command_wrapper.in ${CMAKE_CURRENT_BINARY_DIR}/${PKI_COMMAND} @ONLY)

    install(
        FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${PKI_COMMAND}
        DESTINATION
            ${BIN_INSTALL_DIR}
        PERMISSIONS
            OWNER_EXECUTE OWNER_WRITE OWNER_READ
            GROUP_EXECUTE GROUP_READ
            WORLD_EXECUTE WORLD_READ
    )
endforeach(PKI_COMMAND)
