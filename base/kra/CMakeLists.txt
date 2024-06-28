project(kra NONE)

add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# build pki-kra
javac(pki-kra-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CLI_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_LANG3_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_CORE_JAR}
        ${JACKSON_DATABIND_JAR}
        ${JSS_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR}
        ${JAXRS_API_JAR}
        ${RESTEASY_JAXRS_JAR}
        ${PKI_COMMON_JAR} ${PKI_SERVER_JAR} ${TOMCAT_CATALINA_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-server-jar
)

add_dependencies(java pki-kra-classes)

set(PKI_KRA_JAR ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    CACHE INTERNAL "pki-kra.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-kra-jar
    CREATE
        ${PKI_KRA_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-kra-classes
)

add_dependencies(java pki-kra-jar)

# Create links at /usr/share/pki/kra/webapps/kra/admin/console.
# Create links in /usr/share/pki/kra/webapps/kra/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-kra-links ALL
    COMMENT "Creating links for KRA")

add_custom_command(
    TARGET pki-kra-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ../../../../../../..${DATA_INSTALL_DIR}/server/webapps/pki/admin/console webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../lib/slf4j-api.jar webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../lib/slf4j-jdk14.jar webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-kra.jar webapp/lib/pki-kra.jar
    COMMAND ln -sf ../../../../../../../..${RESTEASY_SERVLET_INITIALIZER_JAR} webapp/lib/resteasy-servlet-intializer.jar
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_KRA_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)

# install directories
install(
    DIRECTORY
        bin/
    DESTINATION
        ${DATA_INSTALL_DIR}/kra/bin
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        database/
    DESTINATION
        ${DATA_INSTALL_DIR}/kra/database
)

install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PATTERN
        "CMakeLists.txt" EXCLUDE
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin/
    DESTINATION
        ${DATA_INSTALL_DIR}/kra/webapps/kra/admin
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/kra/webapps/kra/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/kra
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/kra
)

