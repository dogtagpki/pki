//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldapconn;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides <LDAP>.ldapconn.* parameters.
 */
public class LDAPConnectionConfig extends ConfigStore {

    public LDAPConnectionConfig(ConfigStorage storage) {
        super(storage);
    }

    public LDAPConnectionConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns <LDAP>.ldapconn.secureConn parameter.
     */
    public boolean isSecure() throws EBaseException {
        return getBoolean(LdapConnInfo.PROP_SECURE, false);
    }

    public void setSecure(boolean secure) throws EBaseException {
        putBoolean(LdapConnInfo.PROP_SECURE, secure);
    }

    /**
     * Returns <LDAP>.ldapconn.host parameter.
     */
    public String getHostname() throws EBaseException {
        return getString(LdapConnInfo.PROP_HOST);
    }

    public void setHostname(String hostname) throws EBaseException {
        putString(LdapConnInfo.PROP_HOST, hostname);
    }

    /**
     * Returns <LDAP>.ldapconn.port parameter.
     */
    public int getPort() throws EBaseException {
        return getInteger(LdapConnInfo.PROP_PORT);
    }

    public void setPort(int port) throws EBaseException {
        putInteger(LdapConnInfo.PROP_PORT, port);
    }

    /**
     * Returns <LDAP>.ldapconn.version parameter.
     */
    public int getVersion() throws EBaseException {
        return getInteger(LdapConnInfo.PROP_VERSION, LdapConnInfo.LDAP_VERSION_3);
    }

    /**
     * Returns <LDAP>.ldapconn.followReferrals parameter.
     */
    public boolean getFollowReferrals() throws EBaseException {
        return getBoolean(LdapConnInfo.PROP_FOLLOW_REFERRALS, true);
    }
}
