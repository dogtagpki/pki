if (UNIX AND _JAVA_TARGET_OUTPUT_LINK)
    if (_JAVA_TARGET_OUTPUT_NAME)
        find_program(LN_EXECUTABLE
            NAMES
                ln
        )

        execute_process(
            COMMAND ${LN_EXECUTABLE} -sf "${_JAVA_TARGET_OUTPUT_NAME}" "${_JAVA_TARGET_OUTPUT_LINK}"
            WORKING_DIRECTORY ${_JAVA_TARGET_DIR}
        )
    else (_JAVA_TARGET_OUTPUT_NAME)
        message(SEND_ERROR "FATAL: Can't find _JAVA_TARGET_OUTPUT_NAME")
    endif (_JAVA_TARGET_OUTPUT_NAME)
endif (UNIX AND _JAVA_TARGET_OUTPUT_LINK)
