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
package com.netscape.cmsutil.password;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;

public class PlainPasswordReader implements IPasswordReader {
    private String mPwdPath = "";
    private Properties mPwdStore;

    public PlainPasswordReader() {
    }

    public void init(String pwdPath)
            throws IOException {
        mPwdStore = new Properties();
        // initialize mPwdStore
        mPwdPath = pwdPath;
        mPwdStore = new Properties();

        FileInputStream file = new FileInputStream(mPwdPath);
        mPwdStore.load(file);
        file.close();
    }

    public String getPassword(String tag) {
        return (String) mPwdStore.getProperty(tag);
    }

    // return an array of String-based tag
    public Enumeration getTags() {
        return mPwdStore.propertyNames();
    }
}
