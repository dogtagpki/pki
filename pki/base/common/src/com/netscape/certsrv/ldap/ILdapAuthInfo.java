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
package com.netscape.certsrv.ldap;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * Class for obtaining ldap authentication info from the configuration store.
 * Two types of authentication is basic and SSL client authentication.
 * 
 * @version $Revision$, $Date$
 */
public interface ILdapAuthInfo {
    static public final String PROP_LDAPAUTHTYPE = "authtype";
    static public final String PROP_CLIENTCERTNICKNAME = "clientCertNickname";
    static public final String PROP_BINDDN = "bindDN";
    static public final String PROP_BINDPW = "bindPassword";
    static public final String PROP_BINDPW_PROMPT = "bindPWPrompt";
    static public final String PROP_BINDDN_DEFAULT = "cn=Directory Manager";

    static public final String LDAP_BASICAUTH_STR = "BasicAuth";
    static public final String LDAP_SSLCLIENTAUTH_STR = "SslClientAuth";

    static public final int LDAP_AUTHTYPE_NONE = 0; // illegal
    static public final int LDAP_AUTHTYPE_BASICAUTH = 1;
    static public final int LDAP_AUTHTYPE_SSLCLIENTAUTH = 2;

    /**
     * Initialize this class from the config store.
     * 
     * @param config The config store from which to initialize.
     * @exception EBaseException Due to failure of the initialization process.
     * 
     */
    public void init(IConfigStore config) throws EBaseException;

    /**
     * Initialize this class from the config store. Based on host, port, and
     * secure boolean info. which allows an actual attempt on the server to
     * verify credentials.
     * 
     * @param config The config store from which to initialize.
     * @exception EBaseException Due to failure of the initialization process.
     * 
     */
    public void init(IConfigStore config, String host, int port, boolean secure)
            throws EBaseException;

    /**
     * Reset the connection to the host
     */
    public void reset();

    /**
     * Get authentication type.
     * 
     * @return one of: <br>
     *         LdapAuthInfo.LDAP_AUTHTYPE_BASICAUTH or
     *         LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH
     */
    public int getAuthType();

    /**
     * Get params for authentication.
     * 
     * @return array of parameters for this authentication as an array of
     *         Strings.
     */
    public String[] getParms();

    /**
     * Add password to private password data structure.
     * 
     * @param prompt Password prompt.
     * @param pw Password itself.
     */
    public void addPassword(String prompt, String pw);

    /**
     * Remove password from private password data structure.
     * 
     * @param prompt Identify password to remove with prompt.
     */
    public void removePassword(String prompt);
}
