project(tps Java)

add_subdirectory(src)

# install files
add_subdirectory(setup)
add_subdirectory(shared/conf)

if(WITH_TOMCAT7)
    add_subdirectory(tomcat7)
endif(WITH_TOMCAT7)

if(WITH_TOMCAT8)
    add_subdirectory(tomcat8)
endif(WITH_TOMCAT8)

# install manual pages
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

# install directories
install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PATTERN
        "CMakeLists.txt" EXCLUDE
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

