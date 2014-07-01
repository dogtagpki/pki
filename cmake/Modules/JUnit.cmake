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
        junit.jar
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

    set(REPORTS_DIR "reports")

    foreach (ARG ${ARGN})
        if (ARG MATCHES "(CLASSPATH|TESTS|REPORTS_DIR)")
            set(TYPE ${ARG})
        
        else (ARG MATCHES "(CLASSPATH|TESTS|REPORTS_DIR)")

            if (TYPE MATCHES "CLASSPATH")
                set(CLASSPATH "${CLASSPATH}${SEPARATOR}${ARG}")

            elseif (TYPE MATCHES "TESTS")
                set(TESTS ${TESTS} ${ARG})

            elseif (TYPE MATCHES "REPORTS_DIR")
                set(REPORTS_DIR ${ARG})

            endif(TYPE MATCHES "CLASSPATH")

        endif(ARG MATCHES "(CLASSPATH|TESTS|REPORTS_DIR)")

    endforeach(ARG)

    add_custom_target(${TARGET_NAME}
        COMMAND
            mkdir -p "${REPORTS_DIR}"
        COMMAND
            ${Java_JAVA_EXECUTABLE}
            -Djunit.reports.dir=${REPORTS_DIR}
            -classpath ${CLASSPATH}
            com.netscape.test.TestRunner
            ${TESTS}
    )

endfunction(add_junit_test)
