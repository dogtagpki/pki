project(pki-ocsp_java NONE)

# build pki-ocsp
javac(pki-ocsp-classes
    SOURCES
        *.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR}
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar
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
        ${CMAKE_CURRENT_BINARY_DIR}/classes
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
