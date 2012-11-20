project(silent NONE)

add_subdirectory(src)
add_subdirectory(scripts)

install(
    FILES
        templates/pki_silent.template
    DESTINATION
        ${DATA_INSTALL_DIR}/silent/
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)

