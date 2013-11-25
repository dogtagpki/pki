project(pki-cmsbundle_java NONE)

# build pki-cmsbundle
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cmsbundle.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cmsbundle.mf
)

jar(pki-cmsbundle-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-cmsbundle.mf
    FILES
        LogMessages.properties
        UserMessages.properties
    DEPENDS
        pki-cmsbundle-jar
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMSBUNDLE_JAR ${CMAKE_BINARY_DIR}/dist/pki-cmsbundle.jar INTERNAL "pki-cmsbundle jar file")
