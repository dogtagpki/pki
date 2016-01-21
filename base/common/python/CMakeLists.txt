find_package(Sphinx REQUIRED)

if(NOT DEFINED SPHINX_THEME)
    set(SPHINX_THEME default)
endif()

if(NOT DEFINED SPHINX_THEME_DIR)
    set(SPHINX_THEME_DIR)
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/conf.py"
    "${CMAKE_CURRENT_BINARY_DIR}/conf.py"
    @ONLY)

add_custom_target(dogtag_python_client_docs ALL
    ${SPHINX_EXECUTABLE}
        -b html
        -c "${CMAKE_CURRENT_SOURCE_DIR}"
        -w "${CMAKE_CURRENT_BINARY_DIR}/python-client-lib-html.log"
        -a
        -W
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/html"
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building Python Client Library HTML documentation")

add_custom_target(dogtag_python_client_man_docs ALL
    ${SPHINX_EXECUTABLE}
        -b man
        -c "${CMAKE_CURRENT_SOURCE_DIR}"
        -w "${CMAKE_CURRENT_BINARY_DIR}/python-client-lib-man.log"
        -a
        -W
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/man"
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building Python Client Library manual pages")

install(
    DIRECTORY
        pki
    DESTINATION
        ${PYTHON2_SITE_PACKAGES}
    FILES_MATCHING PATTERN
        *.py
)

if(PYTHON3_SITE_PACKAGES)
    install(
        DIRECTORY
            pki
        DESTINATION
            ${PYTHON3_SITE_PACKAGES}
        FILES_MATCHING PATTERN
            *.py
    )
endif()

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/html
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/doc/pki-base/
    PATTERN
        .buildinfo EXCLUDE
    PATTERN
        .doctrees EXCLUDE
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/man/
    DESTINATION
        ${MAN_INSTALL_DIR}/man1
    PATTERN
        .buildinfo EXCLUDE
    PATTERN
        .doctrees EXCLUDE
)
