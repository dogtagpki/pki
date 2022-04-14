project(meta)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/README
    ${CMAKE_CURRENT_BINARY_DIR}/README
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/README
    DESTINATION
        ${CMAKE_INSTALL_PREFIX}/share/doc/pki
)
