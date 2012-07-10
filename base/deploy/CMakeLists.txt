project(deploy)

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
    FILES
        scripts/pkidaemon
        src/pkispawn
        src/pkidestroy
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
    FILES
        config/pkideployment.cfg
        config/pkislots.cfg
    DESTINATION
        ${DATA_INSTALL_DIR}/deployment/config
    PERMISSIONS
        OWNER_WRITE OWNER_READ
        GROUP_READ
        WORLD_READ
)

find_package(PythonInterp REQUIRED)
execute_process(
    COMMAND
        ${PYTHON_EXECUTABLE} -c
        "from distutils.sysconfig import get_python_lib; print get_python_lib()"
    OUTPUT_VARIABLE
        PYTHON_SITE_PACKAGES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
install(
    FILES
        src/scriptlets/configuration.jy
        src/scriptlets/configuration.py
        src/scriptlets/finalization.py
        src/scriptlets/infrastructure_layout.py
        src/scriptlets/initialization.py
        src/scriptlets/instance_layout.py
        src/scriptlets/pkiconfig.py
        src/scriptlets/pkihelper.py
        src/scriptlets/pkijython.py
        src/scriptlets/pkilogging.py
        src/scriptlets/pkimanifest.py
        src/scriptlets/pkimessages.py
        src/scriptlets/pkiparser.py
        src/scriptlets/pkiscriptlet.py
        src/scriptlets/security_databases.py
        src/scriptlets/selinux_setup.py
        src/scriptlets/slot_substitution.py
        src/scriptlets/subsystem_layout.py
        src/scriptlets/war_explosion.py
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
                \"\$ENV{DESTDIR}${PYTHON_SITE_PACKAGES}/pki/__init__.py\")"
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

# install subsystem directories for pkispawn and pkidestroy
foreach(PKI_SUBSYSTEM ${PKI_SUBSYSTEMS})
    install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${PKI_SUBSYSTEM})")
    install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${PKI_SUBSYSTEM})")
endforeach(PKI_SUBSYSTEM ${PKI_SUBSYSTEMS})

# generate and install shared ordered 'scriptlet' symbolic links
# for CA, KRA, OCSP, and TKS for pkispawn
foreach(TOMCAT_SUBSYSTEM ${TOMCAT_SUBSYSTEMS})
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/initialization.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/000_initialization\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/infrastructure_layout.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/010_infrastructure_layout\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/instance_layout.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/020_instance_layout\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/subsystem_layout.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/030_subsystem_layout\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/selinux_setup.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/035_selinux_setup\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/war_explosion.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/040_war_explosion\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/slot_substitution.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/050_slot_substitution\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/security_databases.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/060_security_databases\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/configuration.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/070_configuration\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/finalization.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/${TOMCAT_SUBSYSTEM}/999_finalization\")"
    )
endforeach(TOMCAT_SUBSYSTEM ${TOMCAT_SUBSYSTEMS})

# generate and install shared ordered 'scriptlet' symbolic links
# for RA, and TPS for pkispawn

# generate and install shared ordered 'scriptlet' symbolic links
# for CA, KRA, OCSP, and TKS for pkidestroy
foreach(TOMCAT_SUBSYSTEM ${TOMCAT_SUBSYSTEMS})
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/initialization.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/000_initialization\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/configuration.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/930_configuration\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/war_explosion.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/940_war_explosion\")"
    )
#   install(CODE "execute_process(COMMAND
#       ${CMAKE_COMMAND} -E create_symlink
#       \"${PYTHON_SITE_PACKAGES}/pki/deployment/slot_substitution.py\"
#       \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/950_slot_substitution\")"
#   )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/subsystem_layout.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/960_subsystem_layout\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/security_databases.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/970_security_databases\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/instance_layout.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/980_instance_layout\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/selinux_setup.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/985_selinux_setup\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/infrastructure_layout.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/990_infrastructure_layout\")"
    )
    install(CODE "execute_process(COMMAND
        ${CMAKE_COMMAND} -E create_symlink
        \"${PYTHON_SITE_PACKAGES}/pki/deployment/finalization.py\"
        \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/${TOMCAT_SUBSYSTEM}/999_finalization\")"
    )
endforeach(TOMCAT_SUBSYSTEM ${TOMCAT_SUBSYSTEMS})

# generate and install shared ordered 'scriptlet' symbolic links
# for RA, and TPS for pkidestroy
