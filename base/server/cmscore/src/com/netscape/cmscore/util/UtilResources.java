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

import java.util.ListResourceBundle;

/**
 * A class represents a resource bundle for miscellanous utilities
 * <P>
 *
 * @author mikep
 * @version $Revision$, $Date$
 * @see java.util.ListResourceBundle
 */
public class UtilResources extends ListResourceBundle {

    /**
     * Returns the content of this resource.
     */
    public Object[][] getContents() {
        return contents;
    }

    /**
     * Constants. The suffix represents the number of
     * possible parameters.
     */
    public final static String HASH_FILE_CHECK_USAGE = "hashFileCheckUsage";
    public final static String BAD_ARG_COUNT = "badArgCount";
    public final static String NO_SUCH_FILE_1 = "noSuchFile";
    public final static String DIGEST_MATCH_1 = "digestMatch";
    public final static String DIGEST_DONT_MATCH_1 = "digestDontMatch";
    public final static String FILE_TRUNCATED = "fileTruncated";
    public final static String EXCEPTION_1 = "exception";
    public final static String LOG_PASSWORD = "logPassword";
    public final static String NO_USERID = "noUserId";
    public final static String NO_SUCH_USER_2 = "noSuchUser";
    public final static String NO_UID_PERMISSION_2 = "noUidPermission";
    public final static String SHUTDOWN_SIG = "shutdownSignal";
    public final static String RESTART_SIG = "restartSignal";

    static final Object[][] contents = {
            { HASH_FILE_CHECK_USAGE, "usage: HashFileCheck <filename>" },
            { BAD_ARG_COUNT, "incorrect number of arguments" },
            { NO_SUCH_FILE_1, "can''t find file {0}" },
            { FILE_TRUNCATED, "Log file has been truncated." },
            { DIGEST_MATCH_1, "Hash digest matches log file. {0} OK" },
            {
                    DIGEST_DONT_MATCH_1,
                    "Hash digest does NOT match log file. {0} and/or hash file is corrupt or the password is incorrect." },
            { EXCEPTION_1, "Caught unexpected exception {0}" },
            { LOG_PASSWORD, "Please enter the log file hash digest password: " },
            { NO_USERID, "No user id in config file.  Running as {0}" },
            { NO_SUCH_USER_2, "No such user as {0}.  Running as {1}" },
            { NO_UID_PERMISSION_2, "Can''t change process uid to {0}. Running as {1}" },
            { SHUTDOWN_SIG, "Received shutdown signal" },
            { RESTART_SIG, "Received restart signal" },
    };
}
