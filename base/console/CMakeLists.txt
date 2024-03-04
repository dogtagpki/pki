project(console NONE)

# build console classes
javac(pki-console-classes
    SOURCES
        src/main/java/*.java
    CLASSPATH
        ${COMMONS_CLI_JAR}
        ${JAXRS_API_JAR}
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR}
        ${JSS_JAR}
        ${LDAPJDK_JAR}
        ${PKI_COMMON_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-common-jar
)

add_dependencies(java pki-console-classes)

set(PKI_CONSOLE_JAR ${CMAKE_BINARY_DIR}/dist/pki-console.jar
    CACHE INTERNAL "pki-console.jar"
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources/META-INF/MANIFEST.MF
    ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
)

# package console classes and resources
jar(pki-console-jar
    CREATE
        ${PKI_CONSOLE_JAR}
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.MF
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    INPUT_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main/resources
    FILES
        com/netscape/admin/certsrv/images/*.gif
    DEPENDS
        pki-console-classes
)

add_dependencies(java pki-console-jar)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bin/pkiconsole
    ${CMAKE_CURRENT_BINARY_DIR}/bin/pkiconsole
    COPYONLY
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/bin/pkiconsole
    DESTINATION
        ${BIN_INSTALL_DIR}
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

if(WITH_JAVA)
    install(
        FILES
            ${PKI_CONSOLE_JAR}
        DESTINATION
            ${JAVA_JAR_INSTALL_DIR}/pki
    )
endif(WITH_JAVA)
