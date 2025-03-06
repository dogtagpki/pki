project(common-ui)

add_custom_target(pki-server-theme-links ALL
    COMMENT "Creating links for PKI server theme")

add_custom_command(
    TARGET pki-server-theme-links POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory links
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/ca links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/css links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/esc links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/fonts links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/images links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/kra links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/ocsp links/
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/pki.properties links/pki.properties
    COMMAND ln -sf ../../../../../..${DATA_INSTALL_DIR}/common-ui/tks links/
    COMMAND ${CMAKE_COMMAND} -E make_directory fonts
    COMMAND ln -sf ../../../../..${DATA_INSTALL_DIR}/common-ui/fonts/${FONTAWESOME_WEBFONT} fonts/fontawesome-webfont.woff
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/links/
    DESTINATION
        ${DATA_INSTALL_DIR}/server/webapps/pki
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/fonts/
    DESTINATION
        ${DATA_INSTALL_DIR}/common-ui/fonts
)

install(
    DIRECTORY
        shared/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/CS_SERVER_VERSION
    ${CMAKE_CURRENT_BINARY_DIR}/CS_SERVER_VERSION
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/CS_SERVER_VERSION
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/pki.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/pki.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/pki.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/404.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/404.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/500.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/500.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/services.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/services.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/404.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/500.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/services.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/ca
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/admin/ca/securitydomainlogin.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/admin/ca/securitydomainlogin.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/admin/ca/sendCookie.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/admin/ca/sendCookie.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/admin/ca/securitydomainlogin.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/admin/ca/sendCookie.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/ca/admin/ca
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/agent/header.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/agent/header.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/agent/index.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/agent/index.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/agent/ports.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/agent/ports.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/agent/header.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/agent/index.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/agent/ports.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/ca/agent
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ca/ee/ca/index.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/ee/ca/index.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ca/ee/ca/index.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/ca/ee/ca
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/kra/404.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/404.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/kra/500.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/500.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/kra/services.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/services.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/404.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/500.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/services.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/kra
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/kra/agent/header.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/agent/header.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/kra/agent/index.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/agent/index.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/agent/header.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/agent/index.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/kra/agent
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/kra/agent/kra/top.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/agent/kra/top.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/kra/agent/kra/top.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/kra/agent/kra
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ocsp/404.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/404.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ocsp/500.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/500.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ocsp/services.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/services.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/404.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/500.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/services.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/ocsp
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ocsp/agent/header.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/agent/header.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ocsp/agent/index.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/agent/index.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/ocsp/agent/ports.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/agent/ports.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/agent/header.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/agent/index.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/ocsp/agent/ports.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/ocsp/agent
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/tks/404.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/404.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/tks/500.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/500.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/tks/services.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/services.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/404.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/500.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/services.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/tks
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/tks/agent/header.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/agent/header.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/tks/agent/index.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/agent/index.properties
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/shared/tks/agent/ports.properties
    ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/agent/ports.properties
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/agent/header.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/agent/index.properties
        ${CMAKE_CURRENT_BINARY_DIR}/shared/tks/agent/ports.properties
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/${PROJECT_NAME}/tks/agent
)
