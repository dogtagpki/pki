project(pki-silent_java NONE)

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
        symkey-jar pki-cmsutil-jar pki-nsutil-jar pki-certsrv-jar pki-cms-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-silent.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-silent.mf
)

jar(pki-silent-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-silent.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-silent.mf
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

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-silent.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_SILENT_JAR ${CMAKE_BINARY_DIR}/dist/pki-silent.jar CACHE INTERNAL "pki-silent jar file")
