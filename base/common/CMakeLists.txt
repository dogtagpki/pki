project(common Java)

# install systemd scripts
install(
    FILES
        shared/lib/systemd/system/pki-tomcatd.target
        shared/lib/systemd/system/pki-tomcatd@.service
    DESTINATION
        ${SYSTEMD_LIB_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        setup/CertServer.directory
        setup/menu.xml
        setup/pkidaemon_registry
    DESTINATION
        ${DATA_INSTALL_DIR}/setup/
    PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
)

# install directories
install(
    DIRECTORY
        shared/
    DESTINATION
        ${DATA_INSTALL_DIR}/shared/
    PATTERN
        "lib/*" EXCLUDE
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/tomcat
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/tomcat
)

install(
    DIRECTORY
    DESTINATION 
        ${SYSTEMD_ETC_INSTALL_DIR}/pki-tomcatd.target.wants
)

add_subdirectory(src)
add_subdirectory(test)
