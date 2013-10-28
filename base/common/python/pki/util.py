#!/usr/bin/python
# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

import os
import shutil

def copy(source, dest):
    """
    Copy a file or a folder and its contents.
    """

    # remove trailing slashes
    if source[-1] == '/': source = source[:-1]
    if dest[-1] == '/': dest = dest[:-1]

    sourceparent = os.path.dirname(source)
    destparent = os.path.dirname(dest)

    copydirs(sourceparent, destparent)

    if os.path.isfile(source):
        copyfile(source, dest)

    else:
        for sourcepath, _, filenames in os.walk(source):

            relpath = sourcepath[len(source):]
            destpath = dest + relpath
            if destpath == '': destpath = '/'

            copydirs(sourcepath, destpath)

            for filename in filenames:
                sourcefile = os.path.join(sourcepath, filename)
                targetfile = os.path.join(destpath, filename)
                copyfile(sourcefile, targetfile)

def copyfile(source, dest, overwrite=True):
    """
    Copy a file or link while preserving its attributes.
    """

    # if dest already exists and not overwriting, do nothing
    if os.path.exists(dest) and not overwrite:
        return

    if os.path.islink(source):
        target = os.readlink(source)
        os.symlink(target, dest)

        st = os.lstat(source)
        os.lchown(dest, st.st_uid, st.st_gid)

    else:
        shutil.copyfile(source, dest)

        st = os.stat(source)
        os.utime(dest, (st.st_atime, st.st_mtime))
        os.chmod(dest, st.st_mode)
        os.chown(dest, st.st_uid, st.st_gid)

def copydirs(source, dest):
    """
    Copy a folder and its parents while preserving their attributes.
    """

    if os.path.exists(dest):
        return

    destparent = os.path.dirname(dest)

    if not os.path.exists(destparent):
        sourceparent = os.path.dirname(source)
        copydirs(sourceparent, destparent)

    os.mkdir(dest)

    st = os.stat(source)
    os.utime(dest, (st.st_atime, st.st_mtime))
    os.chmod(dest, st.st_mode)
    os.chown(dest, st.st_uid, st.st_gid)
