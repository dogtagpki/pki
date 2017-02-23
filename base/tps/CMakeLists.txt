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

# Create /usr/share/pki/tps/webapps/tps/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-tps-lib ALL)

add_custom_command(
    TARGET pki-tps-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-nsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-nsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmscore.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmscore.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-tps.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-tps.jar
)

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

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/tps/webapps/tps/WEB-INF/lib
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

