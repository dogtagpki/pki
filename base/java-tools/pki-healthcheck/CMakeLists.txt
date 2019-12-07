project(pki-healthcheck)

# Execute build for pki-healthcheck

set(target "pki-healthcheck")

# healthcheck is NOT supported in python2
set(PYTHON "python3")

set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py")
set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
set(SRC_DIR    "pkihealthcheck")
set(INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/install")

configure_file(${SETUP_PY_IN} ${SETUP_PY})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pki-healthcheck.conf ${CMAKE_CURRENT_BINARY_DIR}/pki-healthcheck.conf @ONLY)

add_custom_target(${target} ALL
    DEPENDS ${SETUP_PY}
    COMMENT "Building Python sources for ${target}")

# Create install directory to store the exec and egg files
file(MAKE_DIRECTORY ${INSTALL_DIR})

# Execute `python setup.py build && python setup.py install`
add_custom_command(
    TARGET ${target}
    COMMAND ${CMAKE_COMMAND}
        -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_DIR} ${CMAKE_CURRENT_BINARY_DIR}/${SRC_DIR}
    COMMAND ${PYTHON} ${SETUP_PY} build
    COMMAND ${PYTHON} ${SETUP_PY} install --root ${INSTALL_DIR}
)

# Install the files to appropriate locations
install(
    FILES
        ${INSTALL_DIR}${BIN_INSTALL_DIR}/pki-healthcheck
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

install(
    DIRECTORY
        ${INSTALL_DIR}${PYTHON3_SITE_PACKAGES}/
    DESTINATION
        ${PYTHON3_SITE_PACKAGES}
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/pki-healthcheck.conf
    DESTINATION
        ${SYSCONF_INSTALL_DIR}/pki/
)
