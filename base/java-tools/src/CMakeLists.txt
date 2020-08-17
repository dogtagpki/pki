project(pki-tools_java NONE)

# build pki-tools
javac(pki-tools-classes
    SOURCES
        *.java
    CLASSPATH
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR}
        ${XALAN_JAR} ${XERCES_JAR}
        ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${JSS_JAR} ${LDAPJDK_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${COMMONS_CLI_JAR} ${COMMONS_LANG3_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${SLF4J_API_JAR} ${JAXB_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-cmsutil-jar pki-certsrv-jar tkstool
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-tools.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-tools.mf
)

jar(pki-tools-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-tools.mf
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
    COMMAND ln -sf ${SHARE_INSTALL_PREFIX}/pki/java-tools/KRATool.cfg ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.cfg
)

install(
    FILES
        com/netscape/cmstools/KRATool.cfg
        ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.cfg
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/pki/java-tools
)

set(PKI_TOOLS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tools.jar CACHE INTERNAL "pki-tools jar file")
