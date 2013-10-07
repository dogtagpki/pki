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
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Map;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmsutil.util.Utils;

/**
 * FileConfigStore:
 * Extends HashConfigStore with methods to load/save from/to file for
 * persistent storage. This is a configuration store agent who
 * reads data from a file.
 * <P>
 * Note that a LdapConfigStore can be implemented so that it reads the configuration stores from the Ldap directory.
 * <P>
 *
 * @version $Revision$, $Date$
 * @see PropConfigStore
 */
public class FileConfigStore extends PropConfigStore implements
        IConfigStore {

    /**
     *
     */
    private static final long serialVersionUID = 2642124526598175633L;
    private File mFile = null;

    /**
     * Constructs a file configuration store.
     * <P>
     *
     * @param fileName file name
     * @exception EBaseException failed to create file configuration
     */
    public FileConfigStore(String fileName) throws EBaseException {
        super(null); // top-level store without a name
        mFile = new File(fileName);
        if (!mFile.exists()) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_CONFIG_FILE",
                        mFile.getPath()));
        }
        load(fileName);
    }

    /**
     * Loads property file into memory.
     * <P>
     *
     * @param fileName file name
     * @exception EBaseException failed to load configuration
     */
    public void load(String fileName) throws EBaseException {
        try {
            FileInputStream fi = new FileInputStream(fileName);
            BufferedInputStream bis = new BufferedInputStream(fi);

            super.load(bis);
        } catch (IOException e) {
            throw new EBaseException("input stream error " + fileName, e);
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
    public void commit(boolean createBackup) throws EBaseException {
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
        save(mFile.getPath());

        try {
            // Make certain that the original file retains
            // the correct permissions.
            if (!Utils.isNT()) {
                Utils.exec("chmod 00660 " + mFile.getCanonicalPath());
            }
        } catch (Exception e) {
        }
    }

    /**
     * Saves in-memory properties to a specified file.
     * <P>
     * Note that the superclass's save is synchronized. It means no properties can be altered (inserted) at the saving
     * time.
     * <P>
     *
     * @param fileName filename
     * @exception EBaseException failed to save configuration
     */
    public void save(String fileName) throws EBaseException {
        try {
            Map<String, String> map = getProperties();

            FileOutputStream fo = new FileOutputStream(fileName);
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(fo));

            for (String name : map.keySet()) {
                String value = map.get(name);
                writer.println(name + "=" + value);
            }

            writer.close();
            fo.close();
        } catch (IOException e) {
            throw new EBaseException("output stream error " + fileName, e);
        }
    }
}
