// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.util;

import java.io.File;
import java.io.FilenameFilter;

/**
 * checks the filename and directory with the specified filter
 * checks with multiple "*".
 * the filter has to start with a '*' character.
 * this to keep the search the same as in the motif version
 * <P>
 * Copied verbatium from sun.awt.tiny.TinyFileDialogPeer. Used by RollingLogFile expiration code
 * <P>
 *
 * @author mikep
 * @version $Revision$, $Date$
 */
public class FileDialogFilter implements FilenameFilter {

    String filter;

    public FileDialogFilter(String f) {
        filter = f;
    }

    public String toString() {
        return filter;
    }

    /**
     * return true if match
     */
    public boolean accept(File dir, String fileName) {

        File f = new File(dir, fileName);

        if (f.isDirectory()) {
            return true;
        } else {
            return searchPattern(fileName, filter);
        }
    }

    /**
     * start searching
     */
    boolean searchPattern(String fileName, String filter) {
        int filterCursor = 0;

        int filterChar = filter.charAt(filterCursor);

        if (filterCursor == 0 && filterChar != '*') {
            return false;
        }
        String ls = filter.substring(filterCursor + 1);

        return handleStar(fileName, ls);
    }

    /**
     * call this method when character was an *
     */
    boolean handleStar(String fileName, String filter) {
        int ftLen = filter.length();
        int flLen = fileName.length();
        char ftChar;
        char flChar;
        int ftCur = 0;
        int flCur = 0;
        int c = 0;

        if (ftLen == 0) {
            return true;
        }

        while (c < flLen) {
            ftChar = filter.charAt(ftCur);

            if (ftChar == '*') {
                String ls = filter.substring(ftCur + 1);
                String fs = fileName.substring(flCur);

                if (handleStar(fs, ls)) {
                    return true;
                }
                c++;
                flCur = c;
                ftCur = 0;
                continue;
            }
            flChar = fileName.charAt(flCur);

            if (ftChar == flChar) {
                ftCur++;
                flCur++;

                if (flCur == flLen && ftCur == ftLen) {
                    return true;
                }

                if (flCur < flLen && ftCur == ftLen) {
                    return false;
                }

                if (flCur == flLen) {
                    c = flLen;
                }
            } else {
                c++;
                flCur = c;
                ftCur = 0;
                if (c == flLen) {
                    return false;
                }
            }
        }

        for (int i = ftCur; i < ftLen; i++) {
            ftChar = filter.charAt(i);
            if (ftChar != '*') {
                return false;
            }
        }
        return true;
    }
}
