set(console_ui_java Java)

set(CONSOLE_UI_TARGET pki-console-theme-${CONSOLE_UI_VERSION})
set(CONSOLE_UI_JAR "${CMAKE_CURRENT_BINARY_DIR}/${CONSOLE_UI_TARGET}.jar" CACHE INTERNAL "console-ui jar file")

set(console_ui_RCS
    CMSAdminRS.properties
    com/netscape/management/client/theme/theme.properties
    com/netscape/management/client/theme/images/login.gif
    com/netscape/management/client/theme/images/ConsoleBanner.gif
    com/netscape/management/client/theme/images/logo16.gif
    com/netscape/management/client/theme/images/logo32.gif
    com/netscape/admin/certsrv/theme/certmgmt.gif
)

add_jar(${CONSOLE_UI_TARGET} ${console_ui_RCS})

install(
    FILES
        ${CONSOLE_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)
