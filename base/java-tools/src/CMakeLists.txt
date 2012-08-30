project(pki-tools_java Java)

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
        /usr/share/java/resteasy
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        /usr/share/java/resteasy
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        /usr/share/java/resteasy
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
        ${JSS_JAR} ${COMMONS_CODEC_JAR}
        ${APACHE_COMMONS_CLI_JAR} ${APACHE_COMMONS_LANG_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil pki-cmsutil pki-certsrv
)

jar(pki-tools-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tools-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/cmstools/*.class
    DEPENDS
        pki-tools-classes
)

link(pki-tools
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
    DEST
        pki-tools-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-tools-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tools.jar
        ${CMAKE_BINARY_DIR}/dist/pki-tools-${APPLICATION_VERSION}.jar
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
