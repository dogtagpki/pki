# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (C) 2012 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#
# Author: Endi S. Dewata

function(javac target)

    set(source_dir ${CMAKE_CURRENT_SOURCE_DIR})

    foreach (arg ${ARGN})

        if (arg MATCHES "(SOURCE_DIR|SOURCES|EXCLUDE|CLASSPATH|OUTPUT_DIR|DEPENDS)")
            set(param ${arg})

        else ()

            if (param STREQUAL "SOURCE_DIR")
                set(source_dir ${arg})

            elseif (param STREQUAL "SOURCES")
                list(APPEND sources ${arg})

            elseif (param STREQUAL "EXCLUDE")
                list(APPEND exclude ${arg})

            elseif (param STREQUAL "CLASSPATH")
                list(APPEND classpath ${arg})

            elseif (param STREQUAL "OUTPUT_DIR")
                set(output_dir ${arg})

            elseif (param STREQUAL "DEPENDS")
                list(APPEND depends ${arg})

            endif(param STREQUAL "SOURCE_DIR")

        endif(arg MATCHES "(SOURCE_DIR|SOURCES|EXCLUDE|CLASSPATH|OUTPUT_DIR|DEPENDS)")

    endforeach(arg)

    if (UNIX)
        set(separator ":")
    else (UNIX)
        set(separator ";")
    endif(UNIX)

    foreach (path ${classpath})
       set(native_classpath "${native_classpath}${separator}${path}")
    endforeach(path)

    set(file_list "${CMAKE_CURRENT_BINARY_DIR}/${target}.files")

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_COMMAND}
            -Doutput=${file_list}
            -Dinput_dir=${source_dir}
            -Dfiles="${sources}"
            -Dexclude="${exclude}"
            -P ${CMAKE_MODULE_PATH}/JavaFileList.cmake
        COMMAND ${CMAKE_Java_COMPILER}
            ${CMAKE_JAVA_COMPILE_FLAGS}
            -cp ${native_classpath}
            -d ${output_dir}
            @${file_list}
        WORKING_DIRECTORY
            ${source_dir}
    )

endfunction(javac)

function(jar target)

    set(input_dir ${CMAKE_CURRENT_SOURCE_DIR})

    foreach (arg ${ARGN})

        if (arg STREQUAL "CREATE")
            set(param ${arg})
            set(operation "c")

        elseif (arg STREQUAL "UPDATE")
            set(param ${arg})
            set(operation "u")

        elseif (arg MATCHES "(INPUT_DIR|FILES|EXCLUDE|DEPENDS)")
            set(param ${arg})

        else ()

            if (param MATCHES "(CREATE|UPDATE)")
                set(output ${arg})

            elseif (param STREQUAL "INPUT_DIR")
                set(input_dir ${arg})

            elseif (param STREQUAL "FILES")
                list(APPEND files ${arg})

            elseif (param STREQUAL "EXCLUDE")
                list(APPEND exclude ${arg})

            elseif (param STREQUAL "DEPENDS")
                list(APPEND depends ${arg})

            endif(param MATCHES "(CREATE|UPDATE)")

        endif(arg STREQUAL "CREATE")

    endforeach(arg)

    set(file_list "${CMAKE_CURRENT_BINARY_DIR}/${target}.files")

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_COMMAND}
            -Doutput=${file_list}
            -Dinput_dir=${input_dir}
            -Dfiles="${files}"
            -Dexclude="${exclude}"
            -P ${CMAKE_MODULE_PATH}/JavaFileList.cmake
        COMMAND ${CMAKE_Java_ARCHIVE}
            -${operation}f ${output}
            -C ${input_dir} @${file_list}
        WORKING_DIRECTORY ${input_dir}
    )

endfunction(jar)

function(javadoc target)

    set(sourcepath ${CMAKE_CURRENT_SOURCE_DIR})
    set(dest ${CMAKE_CURRENT_BINARY_DIR}/javadoc)

    foreach (arg ${ARGN})

        if (arg MATCHES "(SOURCEPATH|CLASSPATH|FILES|PACKAGES|SUBPACKAGES|EXCLUDE|OPTIONS|DEST|DEPENDS)")
            set(param ${arg})

        else ()

            if (param STREQUAL "SOURCEPATH")
                list(APPEND sourcepath ${arg})

            elseif (param STREQUAL "CLASSPATH")
                list(APPEND classpath ${arg})

            elseif (param STREQUAL "FILES")
                list(APPEND files ${arg})

            elseif (param STREQUAL "PACKAGES")
                list(APPEND packages ${arg})

            elseif (param STREQUAL "SUBPACKAGES")
                list(APPEND subpackages ${arg})

            elseif (param STREQUAL "EXCLUDE")
                list(APPEND exclude ${arg})

            elseif (param STREQUAL "OPTIONS")
                list(APPEND options ${arg})

            elseif (param STREQUAL "DEST")
                set(dest ${arg})

            elseif (param STREQUAL "DEPENDS")
                list(APPEND depends ${arg})

            endif(param STREQUAL "SOURCEPATH")

        endif(arg MATCHES "(SOURCEPATH|CLASSPATH|FILES|PACKAGES|SUBPACKAGES|EXCLUDE|DEST|DEPENDS)")

    endforeach(arg)

    if (UNIX)
        set(separator ":")
    else (UNIX)
        set(separator ";")
    endif(UNIX)

    set(command ${JAVA_DOC} -d ${dest})

    if (options)
        foreach (option ${options})
           set(command ${command} ${option})
        endforeach(option ${options})
    endif(sourcepath)

    if (sourcepath)
        set(tmp)
        foreach (path ${sourcepath})
           set(tmp "${tmp}${separator}${path}")
        endforeach(path)
        set(command ${command} -sourcepath ${tmp})
    endif(sourcepath)

    if (classpath)
        set(tmp)
        foreach (path ${classpath})
           set(tmp "${tmp}${separator}${path}")
        endforeach(path)
        set(command ${command} -classpath ${tmp})
    endif(classpath)

    if (subpackages)
        set(tmp)
        foreach (package ${subpackages})
           set(tmp "${tmp}:${package}")
        endforeach(path)
        set(command ${command} -subpackages ${tmp})
    endif(subpackages)

    if (exclude)
        set(tmp)
        foreach (package ${exclude})
           set(tmp "${tmp}:${package}")
        endforeach(path)
        set(command ${command} -exclude ${tmp})
    endif(exclude)

    set(command ${command} ${files} ${packages})

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${command}
    )

endfunction(javadoc)

function(link target)

    foreach (arg ${ARGN})

        if (arg MATCHES "(SOURCE|DEST|DEPENDS)")
            set(param ${arg})

        else ()

            if (param STREQUAL "SOURCE")
                set(source ${arg})

            elseif (param STREQUAL "DEST")
                set(dest ${arg})

            elseif (param STREQUAL "DEPENDS")
                list(APPEND depends ${arg})

            endif(param STREQUAL "SOURCE")

        endif(arg MATCHES "(SOURCE|DEST|DEPENDS)")

    endforeach(arg)

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_COMMAND}
            -E create_symlink ${dest} ${source}
    )

endfunction(link)