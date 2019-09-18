project(pki-certsrv_java NONE)

# build pki-certsrv
javac(pki-certsrv-classes
    SOURCES
        *.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${LDAPJDK_JAR} ${SERVLET_JAR} ${VELOCITY_JAR} ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR} ${COMMONS_IO_JAR}
        ${COMMONS_LANG_JAR} ${COMMONS_CLI_JAR}
        ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR} ${SYMKEY_JAR}
        ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_JAXB_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR} ${RESTEASY_CLIENT_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR} ${JAXB_API_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-certsrv.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-certsrv.mf
)

jar(pki-certsrv-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-certsrv.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-certsrv-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CERTSRV_JAR ${CMAKE_BINARY_DIR}/dist/pki-certsrv.jar CACHE INTERNAL "pki-certsrv jar file")
