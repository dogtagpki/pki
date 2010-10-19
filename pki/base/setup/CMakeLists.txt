project(setup)

install(
    FILES
        pkicommon
        pkicreate
        pkihost
        pkiremove
    DESTINATION
        ${BIN_INSTALL_DIR}
)
