project(pki-ocsp_java NONE)

# '/usr/share/java/pki' jars
find_file(PKI_CERTSRV_JAR
    NAMES
        pki-certsrv.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_CMS_JAR
    NAMES
        pki-cms.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_CMSCORE_JAR
    NAMES
        pki-cmscore.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_CMSUTIL_JAR
    NAMES
        pki-cmsutil.jar
    PATHS
        /usr/share/java/pki
)

find_file(PKI_NSUTIL_JAR
    NAMES
        pki-nsutil.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java/pki
)


# '/usr/share/java' jars
find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        /usr/share/java
)

find_file(JAXRS_API_JAR
    NAMES
        jaxrs-api.jar
    PATHS
        ${RESTEASY_LIB}
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

find_file(SYMKEY_JAR
    NAMES
        symkey.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
)


# build pki-ocsp
javac(pki-ocsp-classes
    SOURCES
        com/netscape/ocsp/*.java
    CLASSPATH
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${PKI_CMSCORE_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_NSUTIL_JAR}
        ${LDAPJDK_JAR} ${JAXRS_API_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${SYMKEY_JAR}
    OUTPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar pki-cmscore-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-ocsp.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-ocsp.mf
)

jar(pki-ocsp-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-ocsp.mf
    INPUT_DIR
        ${CMAKE_BINARY_DIR}/classes
    FILES
        com/netscape/ocsp/*.class
    DEPENDS
        pki-ocsp-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_OCSP_JAR ${CMAKE_BINARY_DIR}/dist/pki-ocsp.jar CACHE INTERNAL "pki-ocsp jar file")
