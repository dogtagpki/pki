project(pki-kra_java NONE)

# build pki-kra
javac(pki-kra-classes
    SOURCES
        *.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_LANG3_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${TOMCAT_CATALINA_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-kra.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-kra.mf
)

jar(pki-kra-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-kra.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-kra-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_KRA_JAR ${CMAKE_BINARY_DIR}/dist/pki-kra.jar CACHE INTERNAL "pki-kra jar file")
