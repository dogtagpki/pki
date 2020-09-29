project(pki-systemd)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-systemd.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-systemd.mf
)

# build systemd classes
javac(pki-systemd-classes
    SOURCES
        *.java
    CLASSPATH
        ${PKI_CMS_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-cms-jar
)

# build pki-systemd.jar
jar(pki-systemd-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-systemd.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-systemd.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-systemd-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-systemd.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_SYSTEMD_JAR ${CMAKE_BINARY_DIR}/dist/pki-systemd.jar CACHE INTERNAL "pki-systemd jar file")
