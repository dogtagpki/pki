project(ocsp Java)

add_subdirectory(src)
add_subdirectory(setup)

# install init script
install(
    FILES
        shared/etc/init.d/pki-ocspd
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/rc.d/init.d
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
        "CMakeLists.txt" EXCLUDE
    PATTERN
        "etc/*" EXCLUDE
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/ocsp
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/ocsp
)
