project(common Java)

install(
    FILES
        scripts/functions
        scripts/pki_apache_initscript
    DESTINATION
        ${DATA_INSTALL_DIR}/scripts/
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        setup/CertServer.directory
        setup/menu.xml
        setup/web-app_2_3.dtd
    DESTINATION
        ${DATA_INSTALL_DIR}/setup/
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

add_subdirectory(src)
