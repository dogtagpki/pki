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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPv2;

/**
 * class for reading ldap connection from the config store.
 * ldap connection info: host, port, secure connection
 */
public class LdapConnInfo {

    public final static String PROP_HOST = "host";
    public final static String PROP_PORT = "port";
    public final static String PROP_SECURE = "secureConn";
    public final static String PROP_VERSION = "version";
    public final static String PROP_FOLLOW_REFERRALS = "followReferrals";
    public final static String PROP_HOST_DEFAULT = "localhost";
    public final static String PROP_PORT_DEFAULT = "389";

    public final static int LDAP_VERSION_2 = 2;
    public final static int LDAP_VERSION_3 = 3;

    private String mHost = null;
    private int mPort = -1;
    private boolean mSecure = false;
    private int mVersion = LDAPv2.PROTOCOL_VERSION;
    private boolean mFollowReferrals = true;

    /**
     * default constructor. must be followed by init(IConfigStore)
     */
    public LdapConnInfo(LDAPConnectionConfig config) throws EBaseException, ELdapException {
        init(config);
    }

    /**
     * initializes an instance from a config store.
     * required parms: host, port
     * optional parms: secure connection, authentication method & info.
     */
    public void init(LDAPConnectionConfig config) throws EBaseException, ELdapException {
        mSecure = config.isSecure();
        mHost = config.getHostname();
        mPort = config.getPort();
        mVersion = config.getVersion();
        mFollowReferrals = config.getFollowReferrals();

        if (mVersion != LDAP_VERSION_2 && mVersion != LDAP_VERSION_3) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY", PROP_VERSION));
        }
        if (mHost == null || mHost.trim().isEmpty()) {
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", PROP_HOST));
        }
        if (mPort <= 0) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY", PROP_PORT));
        }
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
