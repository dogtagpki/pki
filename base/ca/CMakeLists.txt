project(ca NONE)

add_subdirectory(src)
add_subdirectory(setup)
add_subdirectory(shared/conf)

# install systemd scripts
install(
    FILES
        shared/lib/systemd/system/pki-cad.target
        shared/lib/systemd/system/pki-cad@.service
    DESTINATION
        ${SYSTEMD_LIB_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

# install init script
install(
     FILES
        shared/etc/init.d/pki-cad
     DESTINATION
        ${SYSCONF_INSTALL_DIR}/rc.d/init.d
     PERMISSIONS
         OWNER_EXECUTE OWNER_WRITE OWNER_READ
         GROUP_EXECUTE GROUP_READ
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
    PATTERN
        "conf/CS.cfg.in" EXCLUDE
    PATTERN
        "lib/*" EXCLUDE
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/ca
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/ca
)

install(
    DIRECTORY
    DESTINATION 
        ${SYSTEMD_ETC_INSTALL_DIR}/pki-cad.target.wants
)
