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
        ${SYSCONF_INSTALL_DIR}/rc.d/init.d
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        applets/1.3.44724DDE.ijc
        applets/1.4.499dc06c.ijc
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/applets
)

install(
    DIRECTORY
        forms/esc/cgi-bin
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
)

install(
    DIRECTORY
        apache/conf
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
)

install(
    FILES
        forms/index.html
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot
)

install(
    FILES
        forms/index.cgi
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        forms/esc/demo
        forms/esc/home
        forms/esc/so
        forms/esc/sow
        forms/tps
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot
    PATTERN
        "forms/esc/sow/css" EXCLUDE
    PATTERN
        "forms/esc/sow/images"EXCLUDE
    PATTERN
        "forms/esc/sow/js"EXCLUDE
    PATTERN
        "forms/tps/admin/console/css"EXCLUDE
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tokendb
)

install(
    DIRECTORY
        lib
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
)

install(
    FILES
        scripts/nss_pcache
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/scripts
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        scripts/addAgents.ldif
        scripts/addIndexes.ldif
        scripts/addTokens.ldif
        scripts/addVLVIndexes.ldif
        scripts/database.ldif
        scripts/schemaMods.ldif
        scripts/vlvtasks.ldif
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/scripts
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/tps
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/tps
)

