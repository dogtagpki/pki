# install init script
install(
    FILES
        etc/init.d/pki-cad
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/init.d
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)
