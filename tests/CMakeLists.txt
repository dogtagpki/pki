project(tests)

install(
    FILES
        tests.yml
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests
)

install(
    DIRECTORY
        dogtag/pytest-ansible/pytest/performance_test/
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/python/performance/
)
