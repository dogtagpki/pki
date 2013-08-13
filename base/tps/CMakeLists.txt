project(tps CXX)

# NOTE:  TPS utilizes internal libraries located under '%{_libdir}/tps'.
#
#        One method of resolving this issue is the use of RPATH as
#        described in 'http://www.cmake.org/Wiki/CMake_RPATH_handling'.
#
#        While Fedora allows the use of RPATH for this purpose as documented
#        in the section entitled 'Rpath_for_Internal_Libraries' in the URL
#        called 'http://fedoraproject.org/wiki/Packaging/Guidelines',
#        the RPM '%cmake' macro overrides use of RPATH on Fedora and RHEL.
#
#        To resolve this issue on Fedora and RHEL, one of the following
#        methods may be utilized:
#
#        (1) Uncomment the 'SET(CMAKE_SKIP_RPATH  FALSE)' line below, or
#        (2) Implement the files described in the section entitled
#            'Alternatives to Rpath' in the URL called
#            'http://fedoraproject.org/wiki/Packaging/Guidelines'.

# use, i.e. don't skip the full RPATH
# (overrides '%cmake' macro setting of true)
#SET(CMAKE_SKIP_RPATH  FALSE)

# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE) 

# the RPATH to be used when installing
SET(CMAKE_INSTALL_RPATH "${LIB_INSTALL_DIR}/tps")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

add_subdirectory(src)
add_subdirectory(tools)

# install files
add_subdirectory(doc)
add_subdirectory(setup)

# install systemd scripts
install(
    FILES
        lib/systemd/system/pki-tpsd.target
        lib/systemd/system/pki-tpsd@.service
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
        applets/1.4.4d40a449.ijc
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/applets
)

install(
    DIRECTORY
        apache/cgi-bin
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
    DIRECTORY
        apache/docroot
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
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

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/demo
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/home
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/so
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/sow
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tokendb
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tps
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tps/admin
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tps/admin/console
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tps/admin/console/config
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tps/admin/console/img
)

install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/docroot/tps/admin/console/js
)

install(
    DIRECTORY
    DESTINATION
        ${SYSTEMD_ETC_INSTALL_DIR}/pki-tpsd.target.wants
)
