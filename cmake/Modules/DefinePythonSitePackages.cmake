# Python 3 detection

function(find_site_packages pythonexecutable targetname)
    execute_process(
        COMMAND
            ${pythonexecutable} -c
            "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE
            out
        ERROR_VARIABLE
            error
        RESULT_VARIABLE
            result
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(result)
        message(FATAL_ERROR "${pythonexecutable} not found: ${result} / ${error}")
    else()
        message(STATUS "${targetname} ${out}")
        set(${targetname} ${out})
        set(${targetname} ${out} PARENT_SCOPE)
    endif()
endfunction(find_site_packages)

# Find default Python
# When WITH_PYTHON3_DEFAULT is enabled, then require Python 3.
if (WITH_PYTHON3_DEFAULT)
    if (NOT WITH_PYTHON3)
        message(FATAL_ERROR "WITH_PYTHON3_DEFAULT=ON requires WITH_PYTHON3=ON")
    endif(NOT WITH_PYTHON3)
    # find Python interpreter
    set(Python_ADDITIONAL_VERSIONS 3)
    find_package(PythonInterp REQUIRED)
    # FindPythonInterp doesn't restrict version with ADDITIONAL_VERSIONS
    if (PYTHON_VERSION_STRING VERSION_LESS "3.5.0")
        message(FATAL_ERROR "Detect Python interpreter < 3.5.0")
    endif()
endif()
message(STATUS "Building pki.server for ${PYTHON_VERSION_STRING}")

# Find site-packages for Python 3
if (WITH_PYTHON3)
    find_site_packages("python3" PYTHON3_SITE_PACKAGES)
    message(STATUS "Building Python 3 pki client package")
endif(WITH_PYTHON3)
