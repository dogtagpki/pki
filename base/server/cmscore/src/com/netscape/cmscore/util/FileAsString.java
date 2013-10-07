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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class FileAsString {

    protected String mFilename;
    protected long mLastRead = 0;

    private String fileContents = null;
    private Object userObject = null;

    /**
     * This class enables you to get treat a file as a string
     * If the file changes underneath you, it will automatically
     * be read
     */
    public FileAsString(String filename) throws IOException {
        mFilename = filename;
        readFile();
    }

    public boolean fileHasChanged() throws IOException {
        File file = new File(mFilename);
        long lastmodified = file.lastModified();

        return (lastmodified != mLastRead);
    }

    private void readFile()
            throws IOException {
        BufferedReader br = createBufferedReader(mFilename);
        StringBuffer buf = new StringBuffer();
        int bytesread = 0;
        try {
            do {
                char cbuf[] = new char[16];

                bytesread = br.read(cbuf, 0, cbuf.length);
                if (bytesread > 0) {
                    buf.append(cbuf, 0, bytesread);
                }
            } while (bytesread != -1);
        } finally {
            if (br != null)
                br.close();
        }

        fileContents = new String(buf);
    }

    private BufferedReader createBufferedReader(String filename)
            throws IOException {
        Debug.trace("createBufferedReader(filename=" + filename + ")");
        BufferedReader br = null;
        FileReader fr = null;

        try {
            File file = new File(filename);

            mLastRead = file.lastModified();
            fr = new FileReader(file);
            br = new BufferedReader(fr);
            mFilename = filename;
        } catch (IOException e) {
            throw e;
        }
        return br;
    }

    public String getAsString()
            throws IOException {
        if (fileHasChanged()) {
            readFile();
        }
        return fileContents;
    }

    public Object getUserObject() {
        try {
            if (fileHasChanged()) {
                userObject = null;
            }
        } catch (Exception e) {
            userObject = null;
        }
        return userObject;
    }

    public void setUserObject(Object x) {
        userObject = x;
    }

    public String getFilename() {
        return mFilename;
    }

}
