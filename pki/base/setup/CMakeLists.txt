project(setup)

install(
    FILES
        pkicreate
        pkiremove
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        pkicommon.pm
    DESTINATION
        ${DATA_INSTALL_DIR}/scripts/
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki
)
