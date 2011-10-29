project(selinux)

add_subdirectory(src)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/selinux/modules
)

