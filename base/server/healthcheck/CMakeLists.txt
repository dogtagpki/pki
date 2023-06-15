project(pki-healthcheck)

# Execute build for pki-healthcheck

set(target "pki-healthcheck")

# healthcheck is NOT supported in python2
set(PYTHON "python3")

set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py")
set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
set(SRC_DIR     "pki")

configure_file(${SETUP_PY_IN} ${SETUP_PY})

# Customize default healthcheck.conf
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/healthcheck.conf
    ${CMAKE_CURRENT_BINARY_DIR}/healthcheck.conf @ONLY
)

add_custom_target(${target} ALL
    DEPENDS ${SETUP_PY}
    COMMENT "Building Python sources for ${target}")

# Execute `python setup.py build && python setup.py install`
add_custom_command(
    TARGET ${target}
    COMMAND ${CMAKE_COMMAND}
        -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_DIR} ${SRC_DIR}
    COMMAND ${PYTHON} ${SETUP_PY} build
    COMMAND ${PYTHON} ${SETUP_PY} install --root .
        --install-scripts bin
        --install-lib lib
)

# Install the files to appropriate locations
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/bin/pki-healthcheck
    DESTINATION
        ${SBIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/lib/
    DESTINATION
        ${PYTHON3_SITE_PACKAGES}
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/healthcheck.conf
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/pki/
)

