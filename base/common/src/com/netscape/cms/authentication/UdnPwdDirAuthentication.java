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
package com.netscape.cms.authentication;

// ldap java sdk
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;

/**
 * udn/pwd directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UdnPwdDirAuthentication extends DirBasedAuthentication {

    /* required credentials to authenticate. udn and pwd are strings. */
    public static final String CRED_UDN = "udn";
    public static final String CRED_PWD = "pwd";
    protected static String[] mRequiredCreds = { CRED_UDN, CRED_PWD };

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] { PROP_DNPATTERN,
                    PROP_LDAPSTRINGATTRS,
                    PROP_LDAPBYTEATTRS,
                    "ldap.ldapconn.host",
                    "ldap.ldapconn.port",
                    "ldap.ldapconn.secureConn",
                    "ldap.ldapconn.version",
                    "ldap.minConns",
                    "ldap.maxConns",
        };

    static {
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TEXT +
                ";Authenticate the user distinguished name and password provided " +
                "by the user against an LDAP directory. Works with the " +
                "Dir Based Enrollment HTML form");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authentication");
    };

    /**
     * Default constructor, initialization must follow.
     */
    public UdnPwdDirAuthentication() {
        super();
    }

    /**
     * Initializes the UdnPwdDirAuthentication auth manager.
     * <p>
     *
     * @param name - The name for this authentication manager instance.
     * @param implName - The name of the authentication manager plugin.
     * @param config - The configuration store for this instance.
     * @exception EBaseException If an error occurs during initialization.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        super.init(name, implName, config, false);
    }

    /**
     * Authenticates a user based on udn, pwd in the directory.
     *
     * @param authCreds The authentication credentials.
     * @return The user's ldap entry dn.
     * @exception EInvalidCredentials If the udn and password are not valid
     * @exception EBaseException If an internal error occurs.
     */
    protected String authenticate(LDAPConnection conn,
            IAuthCredentials authCreds,
            AuthToken token)
            throws EBaseException {
        String userdn = null;

        // authenticate by binding to ldap server with password.
        try {
            // get the udn.
            userdn = (String) authCreds.get(CRED_UDN);
            if (userdn == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_UDN));
            }

            // get the password.
            String pwd = (String) authCreds.get(CRED_PWD);

            if (pwd == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PWD));
            }
            if (pwd.equals("")) {
                // anonymous binding not allowed
                log(ILogger.LL_FAILURE,
                        "user " + userdn + " attempted login with empty password.");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // bind as user dn and pwd - authenticates user with pwd.
            conn.authenticate(userdn, pwd);
            // set userdn in the token.
            token.set(CRED_UDN, userdn);

            return userdn;
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE,
                    "Couldn't get ldap connection. Error: " + e.toString());
            throw e;
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                log(ILogger.LL_SECURITY,
                        "user " + userdn + " does not exist in ldap server host " +
                                conn.getHost() + ", port " + conn.getPort() + ".");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.INVALID_CREDENTIALS:
                log(ILogger.LL_SECURITY,
                        "authenticate user " + userdn + " with bad password.");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.SERVER_DOWN:
                log(ILogger.LL_FAILURE, "Ldap server is down.");
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            default:
                log(ILogger.LL_FAILURE,
                        "Ldap error encountered. " + e.getMessage());
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_OTHER_LDAP_EXCEPTION",
                                e.errorCodeToString()));
            }
        }
    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * Returns array of required credentials for this authentication manager.
     *
     * @return Array of required credentials.
     */
    public String[] getRequiredCreds() {
        return mRequiredCreds;
    }

}
