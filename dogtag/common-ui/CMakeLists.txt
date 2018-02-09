project(common-ui)

add_custom_target(pki-server-theme-links ALL)

add_custom_command(
    TARGET pki-server-theme-links
    COMMAND ${CMAKE_COMMAND} -E make_directory links
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/ca ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/css ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/esc ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/fonts ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/images ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/kra ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/ocsp ${CMAKE_CURRENT_BINARY_DIR}/links/
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/pki.properties ${CMAKE_CURRENT_BINARY_DIR}/links/pki.properties
    COMMAND /usr/bin/ln -sf ${DATA_INSTALL_DIR}/common-ui/tks ${CMAKE_CURRENT_BINARY_DIR}/links/
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/links/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/webapps/pki
)

install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
)
