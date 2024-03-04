/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.preferences;

import java.io.File;
import java.io.FilenameFilter;
import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.management.client.console.Console;
import com.netscape.management.client.util.Debug;

/**
 * A PreferenceManager that reads and stores preference
 * data from the file system (disk).
 *
 * @author  ahakim@netscape.com
 */
public class FilePreferenceManager extends PreferenceManager {
    private static String FILE_SEPARATOR = ".";
    private static String FILE_SUFFIX = ".preferences";
    private Hashtable _prefTable = new Hashtable();
    private String _baseName;

    public FilePreferenceManager(String product, String version) {
        super(product, version);
        _baseName = product + FILE_SEPARATOR + version + FILE_SEPARATOR;
    }

    public static String getHomePath() {
        File f = new File(Console.PREFERENCE_DIR);
        if (!f.exists())
            f.mkdir();

        if (!f.exists()) {
            Debug.println("error: cannot create/access" + Console.PREFERENCE_DIR);
            return ".";
        }
        return Console.PREFERENCE_DIR;
    }


    public String getBaseName() {
        return _baseName;
    }

    public String[] getPreferencesList() {
        File f = new File(getHomePath());
        String files[] = f.list(new EndsWithFilenameFilter(FILE_SUFFIX));
        String list[] = new String[files.length];
        for (int i = 0; i < files.length; i++) {
            int startIndex = 0;
            if (files[i].startsWith(_baseName))
                startIndex = _baseName.length();
            int endIndex = files[i].length() - FILE_SUFFIX.length();
            list[i] = files[i].substring(startIndex, endIndex);
        }
        return list;
    }

    public Preferences getPreferences(String group) {
        Preferences p = (Preferences)_prefTable.get(_baseName + group);
        if (p == null) {
            p = new FilePreferences(_baseName + group + FILE_SUFFIX);
            _prefTable.put(_baseName + group, p);
        }
        return p;
    }

    public void savePreferences() {
        Enumeration e = _prefTable.elements();
        while (e.hasMoreElements()) {
            Preferences p = (Preferences) e.nextElement();
            p.save();
        }
    }

    public boolean isPreferencesDirty() {
        Enumeration e = _prefTable.elements();
        while (e.hasMoreElements()) {
            Preferences p = (Preferences) e.nextElement();
            if (p.isDirty())
                return true;
        }
        return false;
    }
}

class EndsWithFilenameFilter implements FilenameFilter {
    String _filter;

    public EndsWithFilenameFilter(String filter) {
        _filter = filter;
    }

    public boolean accept(File dir, String name) {
        if (name.endsWith(_filter))
            return true;

        return false;
    }
}
