project(pki-tools_java NONE)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(APACHE_COMMONS_CLI_JAR
    NAMES
        apache-commons-cli.jar
    PATHS
        /usr/share/java
)

find_file(APACHE_COMMONS_LANG_JAR
    NAMES
        apache-commons-lang.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_IO_JAR
    NAMES
        commons-io.jar
    PATHS
        /usr/share/java
)

find_file(XALAN_JAR
    NAMES
        xalan-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(JAXRS_API_JAR
    NAMES
        jaxrs-api.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(HTTPCLIENT_JAR
    NAMES
        httpclient.jar
    PATHS
        /usr/share/java/httpcomponents
)

find_file(HTTPCORE_JAR
    NAMES
        httpcore.jar
    PATHS
        /usr/share/java/httpcomponents
)

# build pki-tools
javac(pki-tools-classes
    SOURCES
        com/netscape/cmstools/*.java
    CLASSPATH
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR}
        ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${APACHE_COMMONS_CLI_JAR} ${APACHE_COMMONS_LANG_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar
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
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cmstools/*.class
    DEPENDS
        pki-tools-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

install(
    FILES
        com/netscape/cmstools/DRMTool.cfg
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/pki/java-tools
)

set(PKI_TOOLS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tools.jar CACHE INTERNAL "pki-tools jar file")
