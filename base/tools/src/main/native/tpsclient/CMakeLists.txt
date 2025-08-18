project(tps CXX)

# Beware of rpath
#
# Since the Linux dynamic linker is usually smarter than a hardcoded path,
# we usually do not permit the use of rpath in Fedora.
#
# https://docs.fedoraproject.org/en-US/packaging-guidelines/#_beware_of_rpath

# skip RPATH on all platforms
# https://gitlab.kitware.com/cmake/community/-/wikis/doc/cmake/RPATH-handling#no-rpath-at-all
SET(CMAKE_SKIP_RPATH TRUE)

add_subdirectory(src)
add_subdirectory(tools)

add_custom_target(tpsclient-man ALL
    COMMENT "Creating PKI server manuals")

add_custom_command(
    TARGET tpsclient-man POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory man/man1
    COMMAND go-md2man -in ${CMAKE_SOURCE_DIR}/docs/manuals/man1/tpsclient.1.md -out man/man1/tpsclient.1
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/man/
    DESTINATION
        ${MAN_INSTALL_DIR}
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
)
