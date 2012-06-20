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
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

public class PlainPasswordFile implements IPasswordStore {
    private String mPwdPath = "";
    private Properties mPwdStore;
    private static final String PASSWORD_WRITER_HEADER = "";

    public PlainPasswordFile() {
    }

    public void init(String pwdPath)
            throws IOException {
        mPwdStore = new Properties();
        // initialize mPwdStore
        mPwdPath = pwdPath;
        FileInputStream file = null;
        try {
            file = new FileInputStream(mPwdPath);
            mPwdStore.load(file);
        } finally {
            if (file != null) {
                file.close();
            }
        }
    }

    public String getPassword(String tag) {
        return mPwdStore.getProperty(tag);
    }

    // return an array of String-based tag
    public Enumeration<String> getTags() {
        Enumeration<?> e = mPwdStore.propertyNames();
        Vector<String> v = new Vector<String>();
        while (e.hasMoreElements()) {
            v.add((String) e.nextElement());
        }
        return v.elements();
    }

    public Object putPassword(String tag, String password) {
        return mPwdStore.setProperty(tag, password);
    }

    public void commit()
            throws IOException, ClassCastException, NullPointerException {
        FileOutputStream file = null;
        try {
            file = new FileOutputStream(mPwdPath);
            mPwdStore.store(file, PASSWORD_WRITER_HEADER);
        } finally {
            if (file != null) {
                file.close();
            }
        }
    }
}
