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

function(add_junit_test target)

    if (WIN32 AND NOT CYGWIN)
        set(separator ";")
    else (WIN32 AND NOT CYGWIN)
        set(separator ":")
    endif(WIN32 AND NOT CYGWIN)

    set(reports_dir "reports")

    foreach (arg ${ARGN})
        if (arg MATCHES "(CLASSPATH|TESTS|REPORTS_DIR|DEPENDS)")
            set(param ${arg})

        else (arg MATCHES "(CLASSPATH|TESTS|REPORTS_DIR|DEPENDS)")

            if (param MATCHES "CLASSPATH")
                set(classpath "${classpath}${separator}${arg}")

            elseif (param MATCHES "TESTS")
                set(tests ${tests} ${arg})

            elseif (param MATCHES "REPORTS_DIR")
                set(reports_dir ${arg})

            elseif (param STREQUAL "DEPENDS")
                list(APPEND depends ${arg})

            endif(param MATCHES "CLASSPATH")

        endif(arg MATCHES "(CLASSPATH|TESTS|REPORTS_DIR|DEPENDS)")

    endforeach(arg)

    add_custom_target(${target} ALL
        DEPENDS ${depends}
        COMMENT "Running JUnit ${target}")

    if(WITH_TEST)
        add_custom_command(
            TARGET ${target}
            COMMAND
                mkdir -p "${reports_dir}"
            COMMAND
                ${Java_JAVA_EXECUTABLE}
                -Djunit.reports.dir=${reports_dir}
                -classpath ${classpath}
                com.netscape.test.TestRunner
                ${tests}
        )
    endif(WITH_TEST)

endfunction(add_junit_test)
