set(pki-console-theme_java Java)

jar(pki-console-theme-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-console-theme.jar
    FILES
        CMSAdminRS.properties
        com/netscape/management/client/theme/theme.properties
        com/netscape/management/client/theme/images/login.gif
        com/netscape/management/client/theme/images/ConsoleBanner.gif
        com/netscape/management/client/theme/images/logo16.gif
        com/netscape/management/client/theme/images/logo32.gif
        com/netscape/admin/certsrv/theme/certmgmt.gif
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-console-theme.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CONSOLE_THEME_JAR ${CMAKE_BINARY_DIR}/dist/pki-console-theme.jar
    CACHE INTERNAL "pki-console-theme jar file"
)
