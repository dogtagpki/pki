project(tests)

install(
    FILES
        pylintrc
        tests.yml
        tox.ini
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests
)

install(
    DIRECTORY
        bin/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/bin
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

install(
    DIRECTORY
        acme/bin/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/acme/bin
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

install(
    DIRECTORY
        ca/bin/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/ca/bin
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

install(
    DIRECTORY
        kra/bin/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/kra/bin
    FILE_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

install(
    DIRECTORY
        dogtag/pytest-ansible/pytest/performance_test/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/python/performance/
)
