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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.ldapconn;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class LDAPConfig extends PropConfigStore {

    public LDAPConfig(ConfigStorage storage) {
        super(storage);
    }

    public LDAPConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getBaseDN() throws EBaseException {
        return getString("basedn");
    }

    public String getBaseDN(String defaultBaseDN) throws EBaseException {
        return getString("basedn", defaultBaseDN);
    }

    public void setBaseDN(String baseDN) {
        putString("basedn", baseDN);
    }

    public String getDatabase() throws EBaseException {
        return getString("database");
    }

    public void setDatabase(String database) {
        putString("database", database);
    }

    public LDAPConnectionConfig getConnectionConfig() {
        return getSubStore("ldapconn", LDAPConnectionConfig.class);
    }

    public LDAPAuthenticationConfig getAuthenticationConfig() {
        return getSubStore("ldapauth", LDAPAuthenticationConfig.class);
    }
}
