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
package com.netscape.cmscore.base;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;

/**
 * FileConfigStore:
 * Extends PropConfigStore with methods to load/save from/to file for
 * persistent storage. This is a configuration store agent who
 * reads data from a file.
 * <P>
 *
 * @version $Revision$, $Date$
 * @see PropConfigStore
 */
public class FileConfigStore extends ConfigStorage {

    private File mFile;

    /**
     * Constructs a file configuration store.
     * <P>
     *
     * @param fileName file name
     * @exception EBaseException failed to create file configuration
     */
    public FileConfigStore(String fileName) throws Exception {
        mFile = new File(fileName);
    }

    public File getFile() {
        return mFile;
    }

    public void load(IConfigStore config) throws Exception {

        if (!mFile.exists()) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_CONFIG_FILE", mFile.getPath()));
        }

        try (FileInputStream fi = new FileInputStream(mFile);
                BufferedInputStream bis = new BufferedInputStream(fi)) {
            config.load(bis);
        }
    }

    /**
     * The original config file is copied to
     * <filename>.<current_time_in_milliseconds>.
     * Commits the current properties to the configuration file.
     * <P>
     *
     * @param backup
     */
    public void commit(IConfigStore config, boolean createBackup) throws EBaseException {
        if (createBackup) {
            File newName = new File(mFile.getPath() + "." +
                    Long.toString(System.currentTimeMillis()));

            try {
                if (Utils.isNT()) {
                    // NT is very picky on the path
                    Utils.exec("copy " +
                                mFile.getAbsolutePath().replace('/', '\\') +
                                " " +
                                newName.getAbsolutePath().replace('/',
                                                                   '\\'));
                } else {
                    // Create a copy of the original file which
                    // preserves the original file permissions.
                    Utils.exec("cp -p " + mFile.getAbsolutePath() + " " +
                                newName.getAbsolutePath());
                }

                // Proceed only if the backup copy was successful.
                if (!newName.exists()) {
                    throw new EBaseException("backup copy failed");
                } else {
                    // Make certain that the backup file has
                    // the correct permissions.
                    if (!Utils.isNT()) {
                        Utils.exec("chmod 00660 " + newName.getAbsolutePath());
                    }
                }
            } catch (EBaseException e) {
                throw new EBaseException("backup copy failed");
            }
        }

        // Overwrite the contents of the original file
        // to preserve the original file permissions.

        try (FileOutputStream out = new FileOutputStream(mFile)) {

            config.store(out);

            // Make certain that the original file retains
            // the correct permissions.
            if (!Utils.isNT()) {
                Utils.exec("chmod 00660 " + mFile.getCanonicalPath());
            }

        } catch (Exception e) {
            throw new EBaseException("Unable to save configuration: " + e.getMessage(), e);
        }
    }
}
