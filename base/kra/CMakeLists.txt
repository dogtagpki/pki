project(kra NONE)

add_subdirectory(src)
add_subdirectory(setup)
add_subdirectory(shared/conf)
add_subdirectory(${APP_SERVER})

# Create links at /usr/share/pki/kra/webapps/kra/admin/console.
# Create links in /usr/share/pki/kra/webapps/kra/WEB-INF/lib.
# This can be customized for different platforms in RPM spec.

add_custom_target(pki-kra-links ALL
    COMMENT "Creating links for KRA")

add_custom_command(
    TARGET pki-kra-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/admin
    COMMAND ln -sf ${DATA_INSTALL_DIR}/server/webapps/pki/admin/console ${CMAKE_CURRENT_BINARY_DIR}/webapp/admin
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_API_JAR} webapp/lib/slf4j-api.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${SLF4J_JDK14_JAR} webapp/lib/slf4j-jdk14.jar
    COMMAND ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
    COMMAND ln -sf /usr/share/java/pki/pki-kra.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-kra.jar
)

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

