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


import java.io.*;
import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.CMS;


/**
 * FileConfigStore:
 * Extends HashConfigStore with methods to load/save from/to file for 
 * persistent storage. This is a configuration store agent who
 * reads data from a file.
 * <P>
 * Note that a LdapConfigStore can be implemented so that it reads 
 * the configuration stores from the Ldap directory.
 * <P>
 * 
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 * @see PropConfigStore
 */
public class FileConfigStore extends PropConfigStore implements 
        IConfigStore {

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
     * The original config file is moved to <filename>.<date>.
     * Commits the current properties to the configuration file.
     * <P>
     *
     * @param backup 
     */
    public void commit(boolean createBackup) throws EBaseException {
        if (createBackup) {
            File newName = new File(mFile.getPath() + "." +
                    Long.toString(System.currentTimeMillis()));

            if (!mFile.renameTo(newName)) {
                throw new EBaseException("rename failed");
            }
        }
        // proceed only if the rename is successful
        save(mFile.getPath());
    }

    /**
     * Saves in-memory properties to a specified file.
     * <P>
     * Note that the superclass's save is synchronized. It
     * means no properties can be altered (inserted) at
     * the saving time.
     * <P>
     *
     * @param fileName filename
     * @exception EBaseException failed to save configuration
     */
    public void save(String fileName) throws EBaseException {
        try {
            FileOutputStream fo = new FileOutputStream(fileName);
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(fo));

            printSubStore(writer, this, "");
            writer.close();
            fo.close();
        } catch (IOException e) {
            throw new EBaseException("output stream error " + fileName, e);
        }
    }

    private void printSubStore(PrintWriter writer, IConfigStore store,
        String name) throws EBaseException,
            IOException {
        // print keys
        Enumeration e0 = store.getPropertyNames();
        Vector v = new Vector();

        while (e0.hasMoreElements()) {
            v.addElement(e0.nextElement());
        }

        // sorting them lexicographically
        while (v.size() > 0) {
            String pname = (String) v.firstElement();
            int j = 0;

            for (int i = 1; i < v.size(); i++) {
                String s = (String) v.elementAt(i);

                if (pname.compareTo(s) > 0) {
                    j = i;
                    pname = (String) v.elementAt(i);
                }
            }
            v.removeElementAt(j);
            writer.println(name + pname + "=" + store.getString(pname));
        }

        // print substores
        Enumeration e1 = store.getSubStoreNames();

        while (e1.hasMoreElements()) {
            v.addElement(e1.nextElement());
        }
        while (v.size() > 0) {
            String pname = (String) v.firstElement();
            int j = 0;

            for (int i = 1; i < v.size(); i++) {
                String s = (String) v.elementAt(i);

                if (pname.compareTo(s) > 0) {
                    j = i;
                    pname = (String) v.elementAt(i);
                }
            }
            v.removeElementAt(j);
            printSubStore(writer, store.getSubStore(pname), name +
                pname + ".");
        }
    }
}
