set(pki-console-theme_java Java)

set(PKI_CONSOLE_THEME_JAR ${CMAKE_BINARY_DIR}/dist/pki-console-theme.jar
    CACHE INTERNAL "pki-console-theme.jar"
)

jar(pki-console-theme-jar
    CREATE
        ${PKI_CONSOLE_THEME_JAR}
    FILES
        CMSAdminRS.properties
        com/netscape/management/client/theme/theme.properties
        com/netscape/management/client/theme/images/login.gif
        com/netscape/management/client/theme/images/ConsoleBanner.gif
        com/netscape/management/client/theme/images/logo16.gif
        com/netscape/management/client/theme/images/logo32.gif
        com/netscape/admin/certsrv/theme/certmgmt.gif
)

add_dependencies(theme pki-console-theme-jar)

install(
    FILES
        ${PKI_CONSOLE_THEME_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)
