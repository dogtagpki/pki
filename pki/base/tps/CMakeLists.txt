project(tps CXX)

add_subdirectory(src)
add_subdirectory(tools)

# install files
add_subdirectory(doc)
add_subdirectory(setup)

# install init script
install(
    FILES
        etc/init.d/pki-tpsd
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/init.d
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DESTINATION
        ${LIB_INSTALL_DIR}/${APPLICATION_NAME}/${PROJECT_NAME}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        forms/index.cgi
        forms/index.html
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot
)

install(
    DIRECTORY
        apache/conf
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/conf
)

install(
    DIRECTORY
        forms/esc/cgi-bin
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/cgi-bin
)

# install directories
set(INSTALL_DIRS
    alias
    applets
    lib
    logs
    scripts
)

foreach(INSTALL_DIR ${INSTALL_DIRS})
    install(
        DIRECTORY
            ${INSTALL_DIR}
        DESTINATION
            ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/${INSTALL_DIR}
    )
endforeach(INSTALL_DIR ${INSTALL_DIRS})
