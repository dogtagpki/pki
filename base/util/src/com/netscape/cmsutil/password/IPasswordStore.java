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
import java.util.Map;

import com.netscape.cmsutil.util.NuxwdogUtil;

public interface IPasswordStore {

    /** Construct a password store.
     *
     * If the process was started by Nuxwdog return a NuxwdogPasswordStore.
     * Otherwise the class name is read from the "passwordClass" key in the
     * map, an instance is constructed, its init() method is called with the
     * value of the "passwordFile" key in the map, and the instance is
     * returned.
     */
    public static IPasswordStore getPasswordStore(String id, Map<String, String> kv)
            throws RuntimeException {
        String pwdClass = null;
        String pwdPath = null;

        if (NuxwdogUtil.startedByNuxwdog()) {
            pwdClass = NuxwdogPasswordStore.class.getName();
            // note: pwdPath is expected to be null in this case
        } else {
            pwdClass = kv.get("passwordClass");
            if (pwdClass == null) {
                throw new RuntimeException(
                    "IPasswordStore.getPasswordStore: passwordClass not defined");
            }

            pwdPath = kv.get("passwordFile");
        }

        try {
            IPasswordStore ps = (IPasswordStore) Class.forName(pwdClass).newInstance();
            ps.init(pwdPath);
            ps.setId(id);
            return ps;
        } catch (Exception e) {
            throw new RuntimeException("Failed to construct or initialise password store", e);
        }
    }

    public void init(String pwdPath) throws IOException;

    public String getPassword(String tag, int iteration);

    public Enumeration<String> getTags();

    public Object putPassword(String tag, String password);

    public void commit()
            throws IOException, ClassCastException, NullPointerException;

    public void setId(String id);
}
