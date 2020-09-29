project(ca NONE)

add_subdirectory(src)
add_subdirectory(setup)
add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# Create links at /usr/share/pki/ca/webapps/ca/admin/console.
# Create links in /usr/share/pki/ca/webapps/ca/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-ca-links ALL)

add_custom_command(
    TARGET pki-ca-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ${DATA_INSTALL_DIR}/server/webapps/pki/admin/console ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
    COMMAND ln -sf /usr/share/java/pki/pki-ca.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-ca.jar
)

if(WITH_SYSTEMD_NOTIFICATION)
add_custom_target(pki-ca-links-systemd-jar ALL
    COMMENT "Creating link to pki-systemd.jar for CA webapp library"
    DEPENDS pki-ca-links
    COMMAND ln -sf /usr/share/java/pki/pki-systemd.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-systemd.jar
)
endif(WITH_SYSTEMD_NOTIFICATION)

# install directories
install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PATTERN
        "CMakeLists.txt" EXCLUDE
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin/
    DESTINATION
        ${DATA_INSTALL_DIR}/ca/webapps/ca/admin
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/ca/webapps/ca/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/ca
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/ca
)

