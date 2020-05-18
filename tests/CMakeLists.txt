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
        tests.yml
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests
)
