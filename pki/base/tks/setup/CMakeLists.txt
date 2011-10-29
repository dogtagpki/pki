set(VERSION ${APPLICATION_VERSION})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.desktop.in ${CMAKE_CURRENT_BINARY_DIR}/config.desktop @ONLY)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/config.desktop
        registry_instance
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/setup
)
