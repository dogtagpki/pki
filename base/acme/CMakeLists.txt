project(acme NONE)

javac(pki-acme-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR} ${COMMONS_LANG_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_JAXB_ANNOTATIONS_JAR}
        ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${JSS_JAR} ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR}
        ${PKI_CMS_JAR}
        ${LDAPJDK_JAR}
    DEPENDS
        pki-cmsutil-jar pki-certsrv-jar pki-cms-jar
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-acme-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-acme.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-acme-classes
)

set(PKI_ACME_JAR ${CMAKE_BINARY_DIR}/dist/pki-acme.jar CACHE INTERNAL "pki-acme.jar file")

add_custom_target(pki-acme-links ALL
    COMMENT "Creating links for ACME")

add_custom_command(
    TARGET pki-acme-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${LDAPJDK_JAR} webapp/lib/ldapjdk.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
    COMMAND ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND ln -sf /usr/share/java/pki/pki-acme.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-acme.jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-acme.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

install(
    FILES
        Dockerfile
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/
)

install(
    DIRECTORY
        sbin/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/sbin/
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
        ${DATA_INSTALL_DIR}/acme/conf/
)

install(
    DIRECTORY
        database/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/database/
)

install(
    DIRECTORY
        issuer/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/issuer/
)

install(
    DIRECTORY
        openshift/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/openshift/
)

# install deployment descriptor
install(
    DIRECTORY
        ${APP_SERVER}/conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/conf/
)

# install web application files
install(
    DIRECTORY
        webapps/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/webapps/
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/webapps/acme/WEB-INF/lib
)
