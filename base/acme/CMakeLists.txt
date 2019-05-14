project(acme NONE)

add_subdirectory(src)

add_custom_target(pki-acme-links ALL
    COMMENT "Creating links for ACME")

add_custom_command(
    TARGET pki-acme-links
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND ln -sf /usr/share/java/pki/pki-acme.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-acme.jar
)

install(
    DIRECTORY
        conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/conf/
)

install(
    DIRECTORY
        ${APP_SERVER}/conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/conf/
)

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
