project(tks NONE)

add_subdirectory(src)
add_subdirectory(setup)
add_subdirectory(shared/conf)

if(WITH_TOMCAT7)
    add_subdirectory(tomcat7)
endif(WITH_TOMCAT7)

if(WITH_TOMCAT8)
    add_subdirectory(tomcat8)
endif(WITH_TOMCAT8)

# Create /usr/share/pki/tks/webapps/tks/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-tks-lib ALL)

add_custom_command(
    TARGET pki-tks-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory webapp/lib
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-nsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-nsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsutil.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsutil.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-certsrv.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-certsrv.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cms.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cms.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmscore.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmscore.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-cmsbundle.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-cmsbundle.jar
    COMMAND /usr/bin/ln -sf /usr/share/java/pki/pki-tks.jar ${CMAKE_CURRENT_BINARY_DIR}/webapp/lib/pki-tks.jar
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
        ${DATA_INSTALL_DIR}/tks/webapps/tks/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/tks
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/tks
)

