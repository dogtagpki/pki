project(pki-ca_java NONE)

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
        ${RESTEASY_LIB}
)

find_file(SERVLET_JAR
    NAMES
        servlet.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

# build pki-ca
javac(pki-ca-classes
    SOURCES
        com/netscape/ca/*.java
    CLASSPATH
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
        ${LDAPJDK_JAR} ${JAXRS_API_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR} ${SERVLET_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar pki-cmscore-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-ca.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-ca.mf
)

jar(pki-ca-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-ca.jar
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

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-ca.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CA_JAR ${CMAKE_BINARY_DIR}/dist/pki-ca.jar CACHE INTERNAL "pki-ca jar file")
