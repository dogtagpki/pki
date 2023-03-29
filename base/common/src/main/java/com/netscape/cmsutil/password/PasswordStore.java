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

import java.io.IOException;
import java.util.Enumeration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmsutil.util.NuxwdogUtil;

public abstract class PasswordStore {

    public static Logger logger = LoggerFactory.getLogger(PasswordStore.class);

    /**
     * Construct a password store.
     *
     * If the process was started by Nuxwdog return a NuxwdogPasswordStore.
     * Otherwise the class name is read from the "passwordClass" key in the
     * map, an instance is constructed, its init() method is called with the
     * value of the "passwordFile" key in the map, and the instance is
     * returned.
     */
    public static PasswordStore create(PasswordStoreConfig psc) throws Exception {

        String className;
        String fileName;

        if (NuxwdogUtil.startedByNuxwdog()) {
            className = NuxwdogPasswordStore.class.getName();
            fileName = null;

        } else {
            className = psc.getClassName();
            fileName = psc.getFileName();
        }

        Class<? extends PasswordStore> clazz = Class.forName(className)
                .asSubclass(PasswordStore.class);

        PasswordStore ps = clazz.getDeclaredConstructor().newInstance();
        ps.setId(psc.getID());
        ps.init(fileName);

        return ps;
    }

    public abstract void init(String pwdPath) throws IOException;

    public abstract String getPassword(String tag, int iteration);

    public abstract Enumeration<String> getTags();

    public abstract Object putPassword(String tag, String password);

    public abstract void commit() throws IOException, ClassCastException, NullPointerException;

    public abstract void setId(String id);
}
