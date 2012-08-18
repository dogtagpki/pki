project(java-tools Java)


install(
    FILES
        pki
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

add_subdirectory(src)
add_subdirectory(templates)
