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

import java.util.Properties;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPRebind;
import netscape.ldap.LDAPRebindAuth;
import netscape.ldap.LDAPSocketFactory;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;

/**
 * A LDAP connection that is bound to a server host, port, secure type.
 * and authentication.
 * Makes a LDAP connection and authentication when instantiated.
 * Cannot establish another LDAP connection or authentication after
 * construction. LDAPConnection connect and authentication methods are
 * overridden to prevent this.
 */
public class LdapBoundConnection extends LDAPConnection {
    /**
     *
     */
    private static final long serialVersionUID = -2242077674357271559L;
    // LDAPConnection calls authenticate so must set this for first
    // authenticate call.
    @SuppressWarnings("unused")
    private boolean mAuthenticated;

    /**
     * Instantiates a connection to a ldap server, secure or non-secure
     * connection with Ldap basic bind dn & pw authentication.
     */
    public LdapBoundConnection(
            LdapConnInfo connInfo, LdapAuthInfo authInfo)
            throws LDAPException {
        // this LONG line to satisfy super being the first call. (yuk)
        super(
                authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH ?
                        new LdapJssSSLSocketFactory(authInfo.getParms()[0]) :
                        (connInfo.getSecure() ? new LdapJssSSLSocketFactory() : null));

        // Set option to automatically follow referrals.
        // Use the same credentials to follow referrals; this is the easiest
        // thing to do without any complicated configuration using
        // different hosts.
        // If client auth is used don't have dn and pw to follow referrals.

        boolean followReferrals = connInfo.getFollowReferrals();

        setOption(LDAPv2.REFERRALS,Boolean.valueOf(followReferrals));
        if (followReferrals &&
                authInfo.getAuthType() != LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            LDAPRebind rebindInfo =
                    new ARebindInfo(authInfo.getParms()[0],
                            authInfo.getParms()[1]);

            setOption(LDAPv2.REFERRALS_REBIND_PROC, rebindInfo);
        }

        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            // will be bound to client auth cert mapped entry.
            super.connect(connInfo.getHost(), connInfo.getPort());
            CMS.debug(
                    "Established LDAP connection with SSL client auth to " +
                            connInfo.getHost() + ":" + connInfo.getPort());
        } else { // basic auth
            String binddn = authInfo.getParms()[0];
            String bindpw = authInfo.getParms()[1];

            super.connect(connInfo.getVersion(),
                    connInfo.getHost(), connInfo.getPort(), binddn, bindpw);
            CMS.debug(
                    "Established LDAP connection using basic authentication to" +
                            " host " + connInfo.getHost() +
                            " port " + connInfo.getPort() +
                            " as " + binddn);
        }
    }

    /**
     * Instantiates a connection to a ldap server, secure or non-secure
     * connection with Ldap basic bind dn & pw authentication.
     */
    public LdapBoundConnection(String host, int port, int version,
            LDAPSocketFactory fac,
            String bindDN, String bindPW)
            throws LDAPException {
        super(fac);
        if (bindDN != null) {
            super.connect(version, host, port, bindDN, bindPW);
            CMS.debug(
                    "Established LDAP connection using basic authentication " +
                            " as " + bindDN + " to " + host + ":" + port);
        } else {
            if (fac == null && bindDN == null) {
                throw new IllegalArgumentException(
                        "Ldap bound connection must have authentication info.");
            }
            // automatically authenticated if it's ssl client auth.
            super.connect(version, host, port, null, null);
            CMS.debug(
                    "Established LDAP connection using SSL client authentication " +
                            "to " + host + ":" + port);
        }
    }

    /**
     * Overrides same method in LDAPConnection to do prevent re-authentication.
     */
    public void authenticate(int version, String dn, String pw)
            throws LDAPException {

        /**
         * if (mAuthenticated) {
         * throw new RuntimeException(
         * "this LdapBoundConnection already authenticated: auth(v,dn,pw)");
         * }
         **/
        super.authenticate(version, dn, pw);
        mAuthenticated = true;
    }

    /**
     * Overrides same method in LDAPConnection to do prevent re-authentication.
     */
    public void authenticate(String dn, String pw)
            throws LDAPException {

        /**
         * if (mAuthenticated) {
         * throw new RuntimeException(
         * "this LdapBoundConnection already authenticated: auth(dn,pw)");
         * }
         **/
        super.authenticate(3, dn, pw);
        mAuthenticated = true;
    }

    /**
     * Overrides same method in LDAPConnection to do prevent re-authentication.
     */
    public void authenticate(String dn, String mechs[],
            Properties props, Object getter)
            throws LDAPException {

        /**
         * if (mAuthenticated) {
         * throw new RuntimeException(
         * "this LdapBoundConnection is already authenticated: auth(mechs)");
         * }
         **/
        super.authenticate(dn, mechs, props, getter);
        mAuthenticated = true;
    }

    /**
     * overrides parent's connect to prevent re-connect.
     */
    public void connect(String host, int port) throws LDAPException {
        throw new RuntimeException(
                "this LdapBoundConnection is already connected: conn(host,port)");
    }

    /**
     * overrides parent's connect to prevent re-connect.
     */
    public void connect(int version, String host, int port,
            String dn, String pw) throws LDAPException {
        throw new RuntimeException(
                "this LdapBoundConnection is already connected: conn(version,h,p)");
    }
}

class ARebindInfo implements LDAPRebind {
    private LDAPRebindAuth mRebindAuthInfo = null;

    public ARebindInfo(String binddn, String pw) {
        mRebindAuthInfo = new LDAPRebindAuth(binddn, pw);
    }

    public LDAPRebindAuth getRebindAuthentication(String host, int port) {
        return mRebindAuthInfo;
    }
}
