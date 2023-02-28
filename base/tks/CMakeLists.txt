project(tks NONE)

add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# build pki-tks
javac(pki-tks-classes
    DEPENDS
        pki-common-jar pki-server-jar
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CLI_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_LANG3_JAR}
        ${JACKSON2_ANNOTATIONS_JAR}
        ${JACKSON2_CORE_JAR}
        ${JACKSON2_DATABIND_JAR}
        ${LDAPJDK_JAR}
        ${JSS_JAR} ${JSS_SYMKEY_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR}
        ${PKI_COMMON_JAR} ${PKI_SERVER_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-tks-jar
    DEPENDS
        pki-tks-classes
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-tks.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

# Create links at /usr/share/pki/tks/webapps/tks/admin/console.
# Create /usr/share/pki/tks/webapps/tks/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-tks-links ALL
    COMMENT "Creating links for TKS")

add_custom_command(
    TARGET pki-tks-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ../../../../../../..${DATA_INSTALL_DIR}/server/webapps/pki/admin/console ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../../../..${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-server.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-server.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-tks.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-tks.jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-tks.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_TKS_JAR ${CMAKE_BINARY_DIR}/dist/pki-tks.jar CACHE INTERNAL "pki-tks jar file")

# install directories
install(
    DIRECTORY
        database/
    DESTINATION
        ${DATA_INSTALL_DIR}/tks/database
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
        ${DATA_INSTALL_DIR}/tks/webapps/tks/admin
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/tks/webapps/tks/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/tks
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/tks
)

