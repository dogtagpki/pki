project(pki-tks_java NONE)

# build pki-tks
javac(pki-tks-classes
    SOURCES
        *.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_LANG_JAR}
        ${LDAPJDK_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-tks.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-tks.mf
)

jar(pki-tks-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tks.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-tks.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tks-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tks.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_TKS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tks.jar CACHE INTERNAL "pki-tks jar file")
