project(tests)

if(WITH_TEST)
    # Run pytests against all files under tests/python/
    file(GLOB_RECURSE test_files "${CMAKE_CURRENT_SOURCE_DIR}/python/*.py")

    foreach(unit_test ${test_files})

        # Get the test name by splitting the path and replacing it with ;
        # This creates a new LIST. Then get the last element in the list
        string(REPLACE "/" ";" TEST_PATH_SPLIT ${unit_test})
        list(GET TEST_PATH_SPLIT -1 test_name)

        add_test(
            NAME ${test_name}
            COMMAND pytest ${unit_test}
        )
    endforeach(unit_test)
endif(WITH_TEST)

install(
    FILES
        pki-rpminspect.yaml
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
