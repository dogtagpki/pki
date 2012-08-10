project(pki-silent_java Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
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

# build pki-silent
javac(pki-silent-classes
    SOURCES
        com/netscape/pkisilent/*.java
    CLASSPATH
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
        ${LDAPJDK_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        symkey pki-cmsutil pki-nsutil pki-certsrv pki-cms
)

jar(pki-silent-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-silent-${APPLICATION_VERSION}.jar
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/pkisilent/*.class
    EXCLUDE
        com/netscape/pkisilent/argparser/ArgParserTest*.class
        com/netscape/pkisilent/common/checkRequest.class
    DEPENDS
        pki-silent-classes
)

link(pki-silent
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-silent.jar
    DEST
        pki-silent-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-silent-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-silent.jar
        ${CMAKE_BINARY_DIR}/dist/pki-silent-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_SILENT_JAR ${CMAKE_BINARY_DIR}/dist/pki-silent.jar CACHE INTERNAL "pki-silent jar file")
