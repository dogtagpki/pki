project(server)

set(PKI_SUBSYSTEMS
    ca
    kra
    ocsp
    ra
    tks
    tps
)

set(TOMCAT_SUBSYSTEMS
    ca
    kra
    ocsp
    tks
)

set(APACHE_SUBSYSTEMS
    ra
    tps
)

install(
    DIRECTORY
        man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)

# install Python libraries
install(
    DIRECTORY
        python/
    DESTINATION
        ${PYTHON_SITE_PACKAGES}
)

# install executables
install(
    FILES
        src/pkispawn
        src/pkidestroy
    DESTINATION
        ${SBIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        sbin/pki-server-upgrade
    DESTINATION
        ${SBIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        upgrade
    DESTINATION
        ${DATA_INSTALL_DIR}/server/
    FILE_PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
    PATTERN ".gitignore" EXCLUDE
)

install(
    FILES
        scripts/pkidaemon
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    FILES
        scripts/operations
    DESTINATION
        ${DATA_INSTALL_DIR}/scripts/
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        config
    DESTINATION
        ${DATA_INSTALL_DIR}/deployment
)

# install server configuration files
install(
    DIRECTORY
        etc/
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/pki
)

install(
    FILES
        src/engine/pkiconfig.py
        src/engine/pkihelper.py
        src/engine/pkilogging.py
        src/engine/pkimanifest.py
        src/engine/pkimessages.py
        src/engine/pkiparser.py
        src/engine/pkiscriptlet.py
        src/scriptlets/configuration.py
        src/scriptlets/finalization.py
        src/scriptlets/infrastructure_layout.py
        src/scriptlets/initialization.py
        src/scriptlets/instance_layout.py
        src/scriptlets/security_databases.py
        src/scriptlets/selinux_setup.py
        src/scriptlets/slot_substitution.py
        src/scriptlets/subsystem_layout.py
        src/scriptlets/webapp_deployment.py
    DESTINATION
        ${PYTHON_SITE_PACKAGES}/pki/deployment
    PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
)
install(
    CODE
        "execute_process(
            COMMAND
                ${CMAKE_COMMAND} -E touch
                \"\$ENV{DESTDIR}${PYTHON_SITE_PACKAGES}/pki/deployment/__init__.py\")"
)

# install empty directories
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/lock/pki)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/run/pki)")
