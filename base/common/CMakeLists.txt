project(common Java)

install(
    FILES
        setup/CertServer.directory
        setup/menu.xml
    DESTINATION
        ${DATA_INSTALL_DIR}/setup/
    PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
)

add_subdirectory(src)
add_subdirectory(test)
