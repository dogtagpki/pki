project(tools)

add_subdirectory(src/main/native/p7tool)
add_subdirectory(src/main/native/pistool)
add_subdirectory(src/main/native/revoker)
add_subdirectory(src/main/native/setpin)
add_subdirectory(src/main/native/sslget)
add_subdirectory(src/main/native/tkstool)
add_subdirectory(templates)

javac(pki-tools-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${XALAN_JAR} ${XERCES_JAR}
        ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${COMMONS_CLI_JAR} ${COMMONS_LANG3_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${SLF4J_API_JAR} ${JAXB_API_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-cmsutil-jar pki-certsrv-jar tkstool
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-tools-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tools-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

# Create compatibility symlink for DRMTool.cfg -> KRATool.cfg

add_custom_target(pki-DRMTool-cfg-link ALL
    COMMENT "Creating link for DRMTool.cfg")

add_custom_command(
    TARGET pki-DRMTool-cfg-link
    COMMAND ln -sf ${SHARE_INSTALL_PREFIX}/pki/tools/KRATool.cfg ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.cfg
)

install(
    FILES
        src/main/resources/KRATool.cfg
        ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.cfg
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/pki/tools
)

set(PKI_TOOLS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tools.jar CACHE INTERNAL "pki-tools jar file")

add_custom_target(pki-tools-man ALL
    COMMENT "Creating PKI tools manuals")

add_custom_command(
    TARGET pki-tools-man
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/man/man1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/AtoB.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/AtoB.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/AuditVerify.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/AuditVerify.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/BtoA.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/BtoA.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/CMCEnroll.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/CMCEnroll.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/CMCRequest.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/CMCRequest.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/CMCResponse.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/CMCResponse.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/CMCSharedToken.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/CMCSharedToken.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/KRATool.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/KRATool.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/PKCS10Client.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/PKCS10Client.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/PKICertImport.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/PKICertImport.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/PrettyPrintCert.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/PrettyPrintCert.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/PrettyPrintCrl.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/PrettyPrintCrl.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-audit.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-audit.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-ca-cert.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-ca-cert.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-ca-kraconnector.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-ca-kraconnector.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-ca-profile.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-ca-profile.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-client.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-client.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-group.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-group.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-group-member.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-group-member.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-kra-key.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-kra-key.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-pkcs12.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-pkcs12.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-pkcs12-cert.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-pkcs12-cert.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-pkcs12-key.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-pkcs12-key.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-securitydomain.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-securitydomain.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-tps-profile.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-tps-profile.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-user.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-user.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-user-cert.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-user-cert.1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/pki-user-membership.1.md -out ${CMAKE_CURRENT_BINARY_DIR}/man/man1/pki-user-membership.1
)

# install man pages generated by md2man
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

# Create compatibility symlink for DRMTool.1.gz -> KRATool.1.gz

add_custom_target(pki-DRMTool-man-link ALL
    COMMENT "Creating link for DRMTool man page")

add_custom_command(
    TARGET pki-DRMTool-man-link
    COMMAND ln -sf ${MAN_INSTALL_DIR}/man1/KRATool.1.gz ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.1.gz
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.1.gz
    DESTINATION
        ${MAN_INSTALL_DIR}/man1
    PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/bin/pki
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)
