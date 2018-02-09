project(java-tools NONE)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bin/pki.in
    ${CMAKE_CURRENT_BINARY_DIR}/bin/pki
)

install(
    DIRECTORY
        man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/bin/pki
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

add_subdirectory(src)
add_subdirectory(templates)
