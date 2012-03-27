project(deploy)

install(
    FILES
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
        config/pkideployment.cfg
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
        src/scriptlets/instance.py
        src/scriptlets/pkiconfig.py
        src/scriptlets/pkihelper.py
        src/scriptlets/pkimessages.py
        src/scriptlets/pkilogging.py
        src/scriptlets/pkiscriptlet.py
        src/scriptlets/security_databases.py
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
#install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/lock/pki)")
#install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${VAR_INSTALL_DIR}/run/pki)")

# install subsystem directories for pkispawn
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/ca)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/kra)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/ocsp)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/ra)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/tks)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/tps)")

# install subsystem directories for pkidestroy
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/ca)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/kra)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/ocsp)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/ra)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/tks)")
install(CODE "file(MAKE_DIRECTORY \$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/destroy/tps)")

# generate and install symbolic links for pkispawn CA
install(
    CODE
        "execute_process(
            COMMAND
                ${CMAKE_COMMAND} -E create_symlink
                \"${PYTHON_SITE_PACKAGES}/pki/deployment/instance.py\"
                \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/ca/0010_instance\")"
)
install(
    CODE
        "execute_process(
            COMMAND
                ${CMAKE_COMMAND} -E create_symlink
                    \"${PYTHON_SITE_PACKAGES}/pki/deployment/security_databases.py\"
                    \"\$ENV{DESTDIR}${DATA_INSTALL_DIR}/deployment/spawn/ca/0020_security_databases\")"
)

# generate and install symbolic links for pkispawn KRA

# generate and install symbolic links for pkispawn OCSP

# generate and install symbolic links for pkispawn RA

# generate and install symbolic links for pkispawn TKS

# generate and install symbolic links for pkispawn TPS


# generate and install symbolic links for pkidestroy CA

# generate and install symbolic links for pkidestroy KRA

# generate and install symbolic links for pkidestroy OCSP

# generate and install symbolic links for pkidestroy RA

# generate and install symbolic links for pkidestroy TKS

# generate and install symbolic links for pkidestroy TPS

