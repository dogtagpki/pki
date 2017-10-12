project(pki-cms)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cms.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cms.mf
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMS_JAR ${CMAKE_BINARY_DIR}/dist/pki-cms.jar CACHE INTERNAL "pki-cms jar file")
