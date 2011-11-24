#
# This file provides functions for JUnit support.
#
# Available Functions:
#
#   add_junit_test(<target name> 
#       CLASSPATH [path1 ...]
#       TESTS [class1 ...]
#   )
#
#   This command creates a target for executing JUnit test classes
#   using the specified class path.
#

find_file(JUNIT_JAR
    NAMES
        junit4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

function(add_junit_test TARGET_NAME)

    if (WIN32 AND NOT CYGWIN)
        set(SEPARATOR ";")
    else (WIN32 AND NOT CYGWIN)
        set(SEPARATOR ":")
    endif(WIN32 AND NOT CYGWIN)

    foreach (ARG ${ARGN})
        if (ARG MATCHES "CLASSPATH" OR ARG MATCHES "TESTS")
            set(TYPE ${ARG})
        
        else (ARG MATCHES "TESTS")

            if (TYPE MATCHES "CLASSPATH")
                set(CLASSPATH "${CLASSPATH}${SEPARATOR}${ARG}")

            elseif (TYPE MATCHES "TESTS")
                set(TESTS ${TESTS} ${ARG})

            endif(TYPE MATCHES "TESTS")

        endif(ARG MATCHES "CLASSPATH" OR ARG MATCHES "TESTS")

    endforeach(ARG)

    add_custom_target(${TARGET_NAME}
        COMMAND ${CMAKE_Java_RUNTIME} -classpath ${CLASSPATH} org.junit.runner.JUnitCore ${TESTS}
    )

endfunction(add_junit_test)
