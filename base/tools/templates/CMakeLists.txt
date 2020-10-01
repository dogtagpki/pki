project(tools-wrapper)

set(PKI_PRODUCT pki)
set(PKI_COMMANDS
    AtoB
    AuditVerify
    BtoA
    CMCEnroll
    CMCRequest
    CMCResponse
    CMCRevoke
    CMCSharedToken
    CRMFPopClient
    ExtJoiner
    GenExtKeyUsage
    GenIssuerAltNameExt
    GenSubjectAltNameExt
    HttpClient
    KRATool
    OCSPClient
    PKCS10Client
    PKCS12Export
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

# Create compatibility symlink for DRMTool -> KRATool

add_custom_target(pki-DRMTool-link ALL
    COMMENT "Creating link for DRMTool")

add_custom_command(
    TARGET pki-DRMTool-link
    COMMAND ln -sf ${BIN_INSTALL_DIR}/KRATool ${CMAKE_CURRENT_BINARY_DIR}/DRMTool
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/DRMTool
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pretty_print_cert_command_wrapper.in ${CMAKE_CURRENT_BINARY_DIR}/PrettyPrintCert @ONLY)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/PrettyPrintCert
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pretty_print_crl_command_wrapper.in ${CMAKE_CURRENT_BINARY_DIR}/PrettyPrintCrl @ONLY)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/PrettyPrintCrl
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

