project(acme NONE)

install(
    DIRECTORY
        ${APP_SERVER}/conf/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/conf/
)

install(
    DIRECTORY
        webapps/
    DESTINATION
        ${DATA_INSTALL_DIR}/acme/webapps/
)
