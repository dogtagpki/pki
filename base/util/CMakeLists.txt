project(util NONE)

add_subdirectory(src)
add_subdirectory(test)

install(FILES PKICertImport.bash
        DESTINATION ${BIN_INSTALL_DIR}
        RENAME PKICertImport
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ)
