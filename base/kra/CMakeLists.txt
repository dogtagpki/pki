project(kra NONE)

add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# build pki-kra
javac(pki-kra-classes
    DEPENDS
        pki-certsrv-jar pki-cms-jar
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${JAXB_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CLI_JAR}
        ${COMMONS_CODEC_JAR}
        ${COMMONS_LANG3_JAR}
        ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_CORE_JAR} ${JACKSON2_DATABIND_JAR}
        ${JSS_JAR} ${JSS_SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR}
        ${PKI_CERTSRV_JAR} ${PKI_CMS_JAR} ${TOMCAT_CATALINA_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

jar(pki-kra-jar
    DEPENDS
        pki-kra-classes
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
)

# Create links at /usr/share/pki/kra/webapps/kra/admin/console.
# Create links in /usr/share/pki/kra/webapps/kra/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-kra-links ALL
    COMMENT "Creating links for KRA")

add_custom_command(
    TARGET pki-kra-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ../../../../../../..${DATA_INSTALL_DIR}/server/webapps/pki/admin/console ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf ../../../../../../../..${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ln -sf ../../../../../../../..${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND ln -sf ../../../../../../../..${JAVA_JAR_INSTALL_DIR}/pki/pki-kra.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-kra.jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-kra.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_KRA_JAR ${CMAKE_BINARY_DIR}/dist/pki-kra.jar CACHE INTERNAL "pki-kra jar file")

# install directories
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

