project(acme NONE)

javac(pki-acme-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR}
        ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR} ${COMMONS_LANG3_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_CORE_JAR}
        ${JACKSON_DATABIND_JAR}
        ${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}
        ${JSS_JAR}
        ${LDAPJDK_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_TOMCAT_JAR}
        ${PKI_TOMCAT_IMPL_JAR}
        ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-acme-classes)

set(PKI_ACME_JAR ${CMAKE_BINARY_DIR}/dist/pki-acme.jar
    CACHE INTERNAL "pki-acme.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-acme-jar
    CREATE
        ${PKI_ACME_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-acme-classes
)

add_dependencies(java pki-acme-jar)

add_custom_target(pki-acme-links ALL
    COMMENT "Creating links for ACME")

add_custom_command(
    TARGET pki-acme-links POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../lib/slf4j-api.jar webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../lib/slf4j-jdk14.jar webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-acme.jar webapp/lib/pki-acme.jar
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_ACME_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

install(
    FILES
        Dockerfile
    DESTINATION
        ${DATA_INSTALL_DIR}/acme
)

install(
    DIRECTORY
        bin/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/bin
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

# install configuration files
install(
    DIRECTORY
        conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/conf
)

install(
    DIRECTORY
        database/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/database
)

install(
    DIRECTORY
        issuer/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/issuer
)

install(
    DIRECTORY
        realm/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/realm
)

install(
    DIRECTORY
        openshift/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/openshift
)

# install deployment descriptor
install(
    DIRECTORY
        ${APP_SERVER}/conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/conf
)

# install web application files
install(
    DIRECTORY
        webapps/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/webapps
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/webapps/acme/WEB-INF/lib
)
