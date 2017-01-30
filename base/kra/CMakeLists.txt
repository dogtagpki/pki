project(kra NONE)

add_subdirectory(src)
add_subdirectory(setup)
add_subdirectory(shared/conf)

if(WITH_TOMCAT7)
    add_subdirectory(tomcat7)
endif(WITH_TOMCAT7)

if(WITH_TOMCAT8)
    add_subdirectory(tomcat8)
endif(WITH_TOMCAT8)

# Create /usr/share/pki/kra/webapps/kra/WEB-INF/lib. This can be customized for different platforms in RPM spec.

add_custom_target(pki-kra-lib ALL)

add_custom_command(
    TARGET pki-kra-lib
    COMMAND ${CMAKE_COMMAND} -E make_directory lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-nsutil.jar lib/pki-nsutil.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-cmsutil.jar lib/pki-cmsutil.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-certsrv.jar lib/pki-certsrv.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-cms.jar lib/pki-cms.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-cmscore.jar lib/pki-cmscore.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-cmsbundle.jar lib/pki-cmsbundle.jar
    COMMAND ${CMAKE_COMMAND} -E create_symlink /usr/share/java/pki/pki-kra.jar lib/pki-kra.jar
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
        ${CMAKE_CURRENT_BINARY_DIR}/lib/
    DESTINATION
        ${DATA_INSTALL_DIR}/kra/webapps/kra/WEB-INF/lib
)

# install empty directories
install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/lock/pki/kra
)

install(
    DIRECTORY
    DESTINATION
        ${VAR_INSTALL_DIR}/run/pki/kra
)

