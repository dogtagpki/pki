set(pki-console-theme_java Java)

set(pki-console-theme_java_RCS
    CMSAdminRS.properties
    com/netscape/management/client/theme/theme.properties
    com/netscape/management/client/theme/images/login.gif
    com/netscape/management/client/theme/images/ConsoleBanner.gif
    com/netscape/management/client/theme/images/logo16.gif
    com/netscape/management/client/theme/images/logo32.gif
    com/netscape/admin/certsrv/theme/certmgmt.gif
)

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(pki-console-theme ${pki-console-theme_java_RCS})
install_jar(pki-console-theme ${JAVA_JAR_INSTALL_DIR}/pki)
set(PKI_CONSOLE_THEME_JAR ${pki-console-theme_JAR_FILE} CACHE INTERNAL "pki-console-theme jar file")

