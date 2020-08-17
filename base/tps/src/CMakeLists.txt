project(pki-tps_java NONE)

# build pki-tps
javac(pki-tps-classes
    SOURCES
        *.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_LANG3_JAR}
        ${LDAPJDK_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${VELOCITY_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        symkey-jar pki-cmsutil-jar pki-certsrv-jar pki-cms-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-tps.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-tps.mf
)

jar(pki-tps-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tps.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-tps.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-tps-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tps.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_TPS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tps.jar CACHE INTERNAL "pki-tps jar file")
