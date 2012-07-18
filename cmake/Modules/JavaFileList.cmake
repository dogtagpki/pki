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

file(WRITE ${output} "")

separate_arguments(file_list UNIX_COMMAND ${files})
separate_arguments(exclude_list UNIX_COMMAND ${exclude})

foreach(file ${exclude_list})

    file(GLOB_RECURSE absolute_files "${input_dir}/${file}")

    foreach(absolute_file ${absolute_files})
        file(RELATIVE_PATH relative_file ${input_dir} ${absolute_file})
	    list(APPEND excluded_files ${relative_file})
    endforeach(absolute_file ${absolute_files})

endforeach(file ${exclude_list})

foreach(file ${file_list})

    file(GLOB_RECURSE absolute_files "${input_dir}/${file}")

    foreach(absolute_file ${absolute_files})
        file(RELATIVE_PATH relative_file ${input_dir} ${absolute_file})

        list(FIND excluded_files ${relative_file} index)

        if (${index} EQUAL -1)
	        file(APPEND ${output} "${relative_file}\n")
	    endif(${index} EQUAL -1)

    endforeach(absolute_file ${absolute_files})

endforeach(file ${file_list})
