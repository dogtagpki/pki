project(ca NONE)

add_subdirectory(src)
add_subdirectory(setup)
add_subdirectory(shared/conf)

if(WITH_TOMCAT7)
    add_subdirectory(tomcat7)
endif(WITH_TOMCAT7)

if(WITH_TOMCAT8)
    add_subdirectory(tomcat8)
endif(WITH_TOMCAT8)

# install directories
install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
    PATTERN
        "CMakeLists.txt" EXCLUDE
    PATTERN
        "conf/CS.cfg.in" EXCLUDE
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/ca
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/ca
)

