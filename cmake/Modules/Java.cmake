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

        if (arg MATCHES "(SOURCE_DIR|SOURCES|CLASSPATH|OUTPUT_DIR|DEPENDS)")
            set(param ${arg})

        else (arg MATCHES "(SOURCE_DIR|SOURCES|CLASSPATH|OUTPUT_DIR|DEPENDS)")

            if (param MATCHES "SOURCE_DIR")
                set(source_dir ${arg})

            elseif (param MATCHES "SOURCES")
                list(APPEND sources ${arg})

            elseif (param MATCHES "CLASSPATH")
                list(APPEND classpath ${arg})

            elseif (param MATCHES "OUTPUT_DIR")
                set(output_dir ${arg})

            elseif (param MATCHES "DEPENDS")
                list(APPEND depends ${arg})

            endif(param MATCHES "SOURCE_DIR")

        endif(arg MATCHES "(SOURCE_DIR|SOURCES|CLASSPATH|OUTPUT_DIR|DEPENDS)")

    endforeach(arg)

    if (UNIX)
        set(separator ":")
    else (UNIX)
        set(separator ";")
    endif(UNIX)

    foreach (path ${classpath})
       set(native_classpath "${native_classpath}${separator}${path}")
    endforeach(path)

    set(filelist "${CMAKE_CURRENT_BINARY_DIR}/${target}.files")

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_COMMAND}
            -Doutput=${filelist}
            -Dinput_dir=${source_dir}
            -Dfiles="${sources}"
            -P ${CMAKE_MODULE_PATH}/JavaFileList.cmake
        COMMAND ${CMAKE_Java_COMPILER}
            ${CMAKE_JAVA_COMPILE_FLAGS}
            -cp ${native_classpath}
            -d ${output_dir}
            @${filelist}
        WORKING_DIRECTORY
            ${source_dir}
    )

endfunction(javac)

function(jar target)

    set(input_dir ${CMAKE_CURRENT_SOURCE_DIR})

    foreach (arg ${ARGN})

        if (arg MATCHES "CREATE")
            set(param ${arg})
            set(operation "c")

        elseif (arg MATCHES "UPDATE")
            set(param ${arg})
            set(operation "u")

        elseif (arg MATCHES "(INPUT_DIR|FILES|DEPENDS)")
            set(param ${arg})

        else ()

            if (param MATCHES "(CREATE|UPDATE)")
                set(output ${arg})

            elseif (param MATCHES "INPUT_DIR")
                set(input_dir ${arg})

            elseif (param MATCHES "FILES")
                list(APPEND files ${arg})

            elseif (param MATCHES "DEPENDS")
                list(APPEND depends ${arg})

            endif(param MATCHES "(CREATE|UPDATE)")

        endif(arg MATCHES "CREATE")

    endforeach(arg)

    set(filelist "${CMAKE_CURRENT_BINARY_DIR}/${target}.files")

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_COMMAND}
            -Doutput=${filelist}
            -Dinput_dir=${input_dir}
            -Dfiles="${files}"
            -P ${CMAKE_MODULE_PATH}/JavaFileList.cmake
        COMMAND ${CMAKE_Java_ARCHIVE}
            -${operation}f ${output}
            @${filelist}
        WORKING_DIRECTORY ${input_dir}
    )

endfunction(jar)

function(link target)

    foreach (arg ${ARGN})

        if (arg MATCHES "(SOURCE|DEST|DEPENDS)")
            set(param ${arg})

        else ()

            if (param MATCHES "SOURCE")
                set(source ${arg})

            elseif (param MATCHES "DEST")
                set(dest ${arg})

            elseif (param MATCHES "DEPENDS")
                list(APPEND depends ${arg})

            endif(param MATCHES "SOURCE")

        endif(arg MATCHES "(SOURCE|DEST|DEPENDS)")

    endforeach(arg)

    add_custom_target(${target} ALL DEPENDS ${depends})

    add_custom_command(
        TARGET ${target}
        COMMAND ${CMAKE_COMMAND}
            -E create_symlink ${dest} ${source}
    )

endfunction(link)