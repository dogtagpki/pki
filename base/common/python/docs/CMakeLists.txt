find_package(Sphinx REQUIRED)

if(NOT DEFINED SPHINX_THEME)
    set(SPHINX_THEME default)
endif()

if(NOT DEFINED SPHINX_THEME_DIR)
    set(SPHINX_THEME_DIR)
endif()

# configured documentation tools and intermediate build results
set(BINARY_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/_build")

# Sphinx cache with pickled ReST documents
set(SPHINX_CACHE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_doctrees")

# HTML output directory
set(SPHINX_HTML_DIR "${CMAKE_CURRENT_BINARY_DIR}/../../../../../base/common/html")

# MAN output directory
set(SPHINX_MAN_DIR "${CMAKE_CURRENT_BINARY_DIR}/../../../../../base/common/man/man1")

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/conf.py.in"
    "${BINARY_BUILD_DIR}/conf.py"
    @ONLY)

add_custom_target(dogtag_python_client_docs ALL
    ${SPHINX_EXECUTABLE}
        -b html
        -c "${BINARY_BUILD_DIR}"
        -d "${SPHINX_CACHE_DIR}"
        -a
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${SPHINX_HTML_DIR}"
    COMMENT "Building HTML documentation with Sphinx")

add_custom_target(dogtag_python_client_man_docs ALL
    ${SPHINX_EXECUTABLE}
        -b man
        -c "${BINARY_BUILD_DIR}"
        -d "${SPHINX_CACHE_DIR}"
        -a
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${SPHINX_MAN_DIR}"
    COMMENT "Building man page documentation with Sphinx")

