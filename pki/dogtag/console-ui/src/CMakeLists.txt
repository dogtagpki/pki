set(console_ui_java Java)

set(console_ui_java_SRCS
    ../CMSAdminRS.properties
    com/netscape/management/client/theme/theme.properties
    com/netscape/management/client/theme/images/login.gif
    com/netscape/management/client/theme/images/ConsoleBanner.gif
    com/netscape/management/client/theme/images/logo16.gif
    com/netscape/management/client/theme/images/logo32.gif
    com/netscape/admin/certsrv/theme/certmgmt.gif
)

set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(pki-console-theme_en ${console_ui_java_SRCS})
install_jar(pki-console-theme_en ${JAVA_JAR_INSTALL_DIR})

set(CONSOLE_UI_JAR ${pki-console-theme_en_JAR_FILE} CACHE INTERNAL "console-ui jar file")

