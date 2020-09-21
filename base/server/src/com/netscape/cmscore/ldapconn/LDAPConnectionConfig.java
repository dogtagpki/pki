//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldapconn;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class LDAPConnectionConfig extends PropConfigStore {

    public LDAPConnectionConfig(ConfigStorage storage) {
        super(storage);
    }

    public LDAPConnectionConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean isSecure() throws EBaseException {
        return getBoolean(LdapConnInfo.PROP_SECURE, false);
    }

    public String getHostname() throws EBaseException {
        return getString(LdapConnInfo.PROP_HOST);
    }

    public int getPort() throws EBaseException {
        return getInteger(LdapConnInfo.PROP_PORT);
    }

    public int getVersion() throws EBaseException {
        return getInteger(LdapConnInfo.PROP_VERSION, LdapConnInfo.LDAP_VERSION_3);
    }

    public boolean getFollowReferrals() throws EBaseException {
        return getBoolean(LdapConnInfo.PROP_FOLLOW_REFERRALS, true);
    }
}
