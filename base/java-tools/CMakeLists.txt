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

# Create compatibility symlink for DRMTool.1.gz -> KRATool.1.gz

add_custom_target(pki-DRMTool-man-link ALL
    COMMENT "Creating link for DRMTool man page")

add_custom_command(
    TARGET pki-DRMTool-man-link
    COMMAND ln -sf ${MAN_INSTALL_DIR}/man1/KRATool.1.gz ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.1.gz
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/DRMTool.1.gz
    DESTINATION
        ${MAN_INSTALL_DIR}/man1
    PERMISSIONS
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
