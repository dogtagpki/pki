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

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSocketFactory;
import netscape.ldap.LDAPv2;

/**
 * A LDAP connection that is bound to a server host, port and secure type.
 * Makes a LDAP connection when instantiated.
 * Cannot establish another LDAP connection after construction.
 * LDAPConnection connect methods are overridden to prevent this.
 */
public class LdapAnonConnection extends LDAPConnection {

    /**
     *
     */
    private static final long serialVersionUID = 6671180208419384682L;

    /**
     * instantiates a connection to a ldap server
     */
    public LdapAnonConnection(LdapConnInfo connInfo)
            throws LDAPException {
        super(connInfo.getSecure() ? new LdapJssSSLSocketFactory() : null);

        // Set option to automatically follow referrals.
        // rebind info is also anonymous.
        boolean followReferrals = connInfo.getFollowReferrals();

        setOption(LDAPv2.REFERRALS, Boolean.valueOf(followReferrals));

        if (connInfo.getVersion() == LDAPv2.PROTOCOL_VERSION) {
            super.connect(connInfo.getVersion(),
                connInfo.getHost(), connInfo.getPort(), null, null);
        } else {
            // use the following connect() call because it connects but does
            // not authenticate with an anonymous bind.  This requires LDAPv3.
            super.connect(connInfo.getHost(), connInfo.getPort());
        }
    }

    /**
     * instantiates a connection to a ldap server
     */
    public LdapAnonConnection(String host, int port, int version,
            LDAPSocketFactory fac)
            throws LDAPException {
        super(fac);
        if (version == LDAPv2.PROTOCOL_VERSION) {
            super.connect(version, host, port, null, null);
        } else {
            // use the following connect() call because it connects but does
            // not authenticate with an anonymous bind.  This requires LDAPv3.
            super.connect(host, port);
        }
    }

    /**
     * instantiates a non-secure connection to a ldap server
     */
    public LdapAnonConnection(String host, int port, int version)
            throws LDAPException {
        super();
        if (version == LDAPv2.PROTOCOL_VERSION) {
            super.connect(version, host, port, null, null);
        } else {
            // use the following connect() call because it connects but does
            // not authenticate with an anonymous bind.  This requires LDAPv3.
            super.connect(host, port);
        }
    }

    /**
     * overrides superclass connect.
     * does not allow reconnect.
     */
    public void connect(int version, String host, int port,
            String dn, String pw) throws LDAPException {
        throw new RuntimeException(
                "this LdapAnonConnection already connected: connect(v,h,p)");
    }
}
