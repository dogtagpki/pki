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

import java.io.*;
import com.netscape.management.client.util.Debug;

/**
 * A type of Preferences object that allows values
 * to be persistantly stored on the file system (disk).
 *
 * @author  ahakim@netscape.com
 * @see Preferences
 */
public class FilePreferences extends Preferences {
    String _filename;

    public FilePreferences(String filename) {
        _filename = FilePreferenceManager.getHomePath() + "/" + filename;
    }

    protected InputStream getInputStream() {
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(_filename);
        } catch (FileNotFoundException e) {
            // ignore, no file initially...
        }
        return inStream;
    }

    protected OutputStream getOutputStream() {
        OutputStream outStream = null;
        try {
            outStream = new FileOutputStream(_filename);
        } catch (IOException e) {
            Debug.println("Cannot create preference file: " + _filename);
        }
        return outStream;
    }

    public void clear() {
        super.clear();
    }

    public void delete() {
        File f = new File(_filename);
        f.delete();
    }

    public static void main(String argv[]) {
        Preferences p = new FilePreferences("testPreferences");
        int i = p.getInt("integer", 0);
        Debug.println("read: " + i);
        boolean b = p.getBoolean("boolean");
        Debug.println("read: " + b);
        String s = p.getString("string", "A long string of a's...");
        Debug.println("read: " + s);

        p.set("integer", ++i);
        p.set("boolean", !b);
        p.set("string", s + "a");
        p.save();

        // uncomment to test clear functionality
        //p.clear();
        //System.out.println("clear");
        System.exit(0);
    }
}
