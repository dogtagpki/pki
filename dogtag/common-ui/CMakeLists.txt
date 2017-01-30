project(common-ui)

add_custom_target(pki-server-theme-links ALL)

add_custom_command(
    TARGET pki-server-theme-links
    COMMAND ${CMAKE_COMMAND} -E make_directory links
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/ca links/ca
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/css links/css
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/esc links/esc
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/fonts links/fonts
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/images links/images
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/kra links/kra
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/ocsp links/ocsp
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/pki.properties links/pki.properties
    COMMAND ${CMAKE_COMMAND} -E create_symlink ${DATA_INSTALL_DIR}/common-ui/tks links/tks
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
