project(server-tomcat-7.0)

add_subdirectory(src)

install(
    DIRECTORY
        conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/conf/
)
