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
package com.netscape.cmscore.ldapconn;

import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnInfo;

/**
 * class for reading ldap connection from the config store.
 * ldap connection info: host, port, secure connection
 */
public class LdapConnInfo implements ILdapConnInfo {

    private String mHost = null;
    private int mPort = -1;
    private boolean mSecure = false;
    private int mVersion = LDAPv2.PROTOCOL_VERSION;
    private boolean mFollowReferrals = true;

    /**
     * default constructor. must be followed by init(IConfigStore)
     */
    public LdapConnInfo(IConfigStore config) throws EBaseException, ELdapException {
        init(config);
    }

    /**
     * initializes an instance from a config store.
     * required parms: host, port
     * optional parms: secure connection, authentication method & info.
     */
    public void init(IConfigStore config) throws EBaseException, ELdapException {
        mHost = config.getString(PROP_HOST);
        mPort = config.getInteger(PROP_PORT);
        String version = config.get(PROP_PROTOCOL);

        if (version != null && version.equals("")) {
            // provide a default when this field is blank from the
            // configuration.
            mVersion = LDAP_VERSION_3;
        } else {
            mVersion = config.getInteger(PROP_PROTOCOL, LDAP_VERSION_3);
            if (mVersion != LDAP_VERSION_2 && mVersion != LDAP_VERSION_3) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY", PROP_PROTOCOL));
            }
        }
        if (mHost == null || (mHost.length() == 0) || (mHost.trim().equals(""))) {
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", PROP_HOST));
        }
        if (mPort <= 0) {
            throw new EBaseException(
                    CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY", PROP_PORT));
        }
        mSecure = config.getBoolean(PROP_SECURE, false);
        mFollowReferrals = config.getBoolean(PROP_FOLLOW_REFERRALS, true);
    }

    public LdapConnInfo(String host, int port, boolean secure) {
        mHost = host;
        mPort = port;
        mSecure = secure;
        if (mHost == null || mPort <= 0) {
            // XXX log something here
            throw new IllegalArgumentException("LDAP host or port is null");
        }
    }

    public LdapConnInfo(String host, int port) {
        mHost = host;
        mPort = port;
        if (mHost == null || mPort <= 0) {
            // XXX log something here
            throw new IllegalArgumentException("LDAP host or port is null");
        }
    }

    public String getHost() {
        return mHost;
    }

    public int getPort() {
        return mPort;
    }

    public int getVersion() {
        return mVersion;
    }

    public boolean getSecure() {
        return mSecure;
    }

    public boolean getFollowReferrals() {
        return mFollowReferrals;
    }

}
