project(pki-ca_java Java)

# '/usr/share/java' jars
find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        /usr/share/java
)


# '${JAVA_LIB_INSTALL_DIR}' jars
find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(JAXRS_API_JAR
    NAMES
        jaxrs-api.jar
    PATHS
        /usr/share/java/resteasy
)

# build pki-ca
javac(pki-ca-classes
    SOURCES
        com/netscape/ca/*.java
    CLASSPATH
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
        ${LDAPJDK_JAR} ${JAXRS_API_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        symkey pki-nsutil pki-cmsutil pki-certsrv pki-cms pki-cmscore
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-ca.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-ca.mf
)

jar(pki-ca-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-ca-${APPLICATION_VERSION}.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-ca.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/ca/*.class
    DEPENDS
        pki-ca-classes
)

link(pki-ca
    SOURCE
        ${CMAKE_BINARY_DIR}/dist/pki-ca.jar
    DEST
        pki-ca-${APPLICATION_VERSION}.jar
    DEPENDS
        pki-ca-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-ca.jar
        ${CMAKE_BINARY_DIR}/dist/pki-ca-${APPLICATION_VERSION}.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CA_JAR ${CMAKE_BINARY_DIR}/dist/pki-ca.jar CACHE INTERNAL "pki-ca jar file")
