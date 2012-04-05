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
package com.netscape.cms.servlet.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;

/**
 * CMSFile represents a file from the filesystem cached in memory
 *
 * @version $Revision$, $Date$
 */
public class CMSFile {
    protected String mAbsPath;
    protected long mLastModified;
    protected byte[] mContent;
    protected long mLastAccess = 0;

    protected ILogger mLogger = CMS.getLogger();

    protected CMSFile() {
    }

    public CMSFile(File file) throws IOException, EBaseException {
        mAbsPath = file.getAbsolutePath();
        mLastModified = file.lastModified();
        fillContent(file);
    }

    private void fillContent(File file) throws IOException {
        int fileSize = (int) file.length();

        mContent = new byte[fileSize];
        FileInputStream fileIn = new FileInputStream(file);
        int actualSize = fileIn.read(mContent);
        fileIn.close();

        if (actualSize != fileSize) {
            byte[] actualContent = new byte[actualSize];

            System.arraycopy(mContent, 0, actualContent, 0, actualSize);
            mContent = actualContent;
        }
    }

    public String getAbsPath() {
        return mAbsPath;
    }

    public byte[] getContent() {
        return mContent;
    }

    public long getLastModified() {
        return mLastModified;
    }

    public synchronized long getLastAccess() {
        return mLastAccess;
    }

    public synchronized void setLastAccess(long lastAccess) {
        mLastAccess = lastAccess;
    }

    protected void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, level, ILogger.S_OTHER, "CMSgateway:" + msg);
    }

    public String toString() {
        try {
            return new String(mContent, "UTF8");
        } catch (UnsupportedEncodingException e) {
            return new String(mContent);
        }
    }

    public String toString(String enc) throws UnsupportedEncodingException {
        return new String(mContent, enc);
    }
}
