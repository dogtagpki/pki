project(tks Java)

add_subdirectory(src)
add_subdirectory(setup)

# install init script
install(
    FILES
        shared/etc/init.d/pki-tksd
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/init.d
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        shared/conf/dtomcat5
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

# install directories
install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PATTERN
        "shared/conf/dtomcat5" EXCLUDE
    PATTERN
        "etc/*" EXCLUDE
)
