# define system dependent compiler flags

include(CheckCCompilerFlag)
include(MacroCheckCCompilerFlagSSP)

if (UNIX AND NOT WIN32)
    #
    # Define GNUCC compiler flags
    #
    if (${CMAKE_C_COMPILER_ID} MATCHES GNU)
        # add -Wconversion ?
        #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -pedantic -pedantic-errors")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wmissing-prototypes -Wdeclaration-after-statement")
        # FESCo Ticket #1185 (https://fedorahosted.org/fesco/ticket/1185):
        #       replace '-Wformat-security' with '-Werror=format-security'
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wfloat-equal -Wpointer-arith -Wwrite-strings -Werror=format-security")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-format-attribute")
        # https://sourceware.org/annobin/annobin.html/Test-gaps.html
        # https://sourceware.org/annobin/annobin.html/Test-cf-protection.html
        # https://sourceware.org/annobin/annobin.html/Test-optimization.html
        # https://sourceware.org/annobin/annobin.html/Test-glibcxx-assertions.html
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fplugin=annobin -fcf-protection=full -O2 -D_GLIBCXX_ASSERTIONS")

        # with -fPIC
        check_c_compiler_flag("-fPIC" WITH_FPIC)
        if (WITH_FPIC)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
        endif (WITH_FPIC)

        check_c_compiler_flag_ssp("-fstack-protector-strong" WITH_STACK_PROTECTOR)
        if (WITH_STACK_PROTECTOR)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
        endif (WITH_STACK_PROTECTOR)

        check_c_compiler_flag("-D_FORTIFY_SOURCE=2" WITH_FORTIFY_SOURCE)
        if (WITH_FORTIFY_SOURCE)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2")
        endif (WITH_FORTIFY_SOURCE)
    endif (${CMAKE_C_COMPILER_ID} MATCHES GNU)

    #
    # Check for large filesystem support
    #
    if (CMAKE_SIZEOF_VOID_P MATCHES "8")
        # with large file support
        execute_process(
            COMMAND
                getconf LFS64_CFLAGS
            OUTPUT_VARIABLE
                _lfs_CFLAGS
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    else (CMAKE_SIZEOF_VOID_P MATCHES "8")
        # with large file support
        execute_process(
            COMMAND
                getconf LFS_CFLAGS
            OUTPUT_VARIABLE
                _lfs_CFLAGS
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
    endif (CMAKE_SIZEOF_VOID_P MATCHES "8")
    if (_lfs_CFLAGS)
        string(REGEX REPLACE "[\r\n]" " " "${_lfs_CFLAGS}" "${${_lfs_CFLAGS}}")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_lfs_CFLAGS}")
    endif (_lfs_CFLAGS)

endif (UNIX AND NOT WIN32)

if (MSVC)
    # Suppress warning about "deprecated" functions
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_CRT_SECURE_NO_WARNINGS")
endif (MSVC)
