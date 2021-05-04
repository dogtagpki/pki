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

import java.util.Hashtable;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

/**
 * class for reading ldap authentication info from config store
 */
public class LdapAuthInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapAuthInfo.class);

    public final static String PROP_LDAPAUTHTYPE = "authtype";
    public final static String PROP_CLIENTCERTNICKNAME = "clientCertNickname";
    public final static String PROP_BINDDN = "bindDN";
    public final static String PROP_BINDPW = "bindPassword";
    public final static String PROP_BINDPW_PROMPT = "bindPWPrompt";
    public final static String PROP_BINDDN_DEFAULT = "cn=Directory Manager";

    public final static String LDAP_BASICAUTH_STR = "BasicAuth";
    public final static String LDAP_SSLCLIENTAUTH_STR = "SslClientAuth";

    public final static int LDAP_AUTHTYPE_NONE = 0; // illegal
    public final static int LDAP_AUTHTYPE_BASICAUTH = 1;
    public final static int LDAP_AUTHTYPE_SSLCLIENTAUTH = 2;

    LDAPAuthenticationConfig config;
    String host;
    int port;
    boolean secure;

    protected int mType = -1;
    String bindDN;
    String nickname;

    private boolean mInited = false;

    IPasswordStore passwordStore;
    private static Hashtable<String, String> passwords = new Hashtable<String, String>();

    /**
     * must call init(config) after this constructor.
     */
    public LdapAuthInfo() {
    }

    public String getPasswordFromStore(String prompt) throws EBaseException {
        String pwd = null;
        logger.debug("LdapAuthInfo: getPasswordFromStore: try to get it from password store");

        // hey - should use password store interface to allow different implementations
        // but the problem is, other parts of the system just go directly to the file
        // so calling CMS.getPasswordStore() will give you an outdated one
        /*
                        IConfigStore mainConfig = CMS.getConfigStore();
                        String pwdFile = mainConfig.getString("passwordFile");
                        FileConfigStore pstore = new FileConfigStore(pwdFile);
        */
        logger.debug("LdapAuthInfo: getPasswordFromStore: about to get from passwored store: " + prompt);

        // support publishing dirsrv with different pwd than internaldb

        // Finally, interactively obtain the password from the user
        if (passwordStore != null) {
            logger.debug("LdapAuthInfo: getPasswordFromStore: password store available");
            pwd = passwordStore.getPassword(prompt, 0);
            //            pwd = pstore.getString(prompt);
            if (pwd == null) {
                logger.debug("LdapAuthInfo: getPasswordFromStore: password for " + prompt +
                        " not found, trying internaldb");

                //               pwd = pstore.getString("internaldb");

                pwd = passwordStore.getPassword("internaldb", 0); // last resort
            } else
                logger.debug("LdapAuthInfo: getPasswordFromStore: password found for prompt in password store");
        } else
            logger.debug("LdapAuthInfo: getPasswordFromStore: password store not available: pwdStore is null");

        return pwd;
    }

    /**
     * initialize this class from the config store.
     */
    public void init(LDAPAuthenticationConfig config) throws EBaseException {
        init(config, null, 0, true);
    }

    /**
     * initialize this class from the config store, and verify the password.
     *
     * @param host The host that the directory server is running on.
     *            This will be used to verify the password by attempting to connect.
     *            If it is <code>null</code>, the password will not be verified.
     * @param port The port that the directory server is running on.
     */
    public void init(LDAPAuthenticationConfig config, String host, int port, boolean secure)
            throws EBaseException {

        logger.debug("LdapAuthInfo: init()");

        if (mInited) {
            logger.debug("LdapAuthInfo: already initialized");
            return; // XXX throw exception here ?
        }

        logger.debug("LdapAuthInfo: init begins");

        this.config = config;
        this.host = host;
        this.port = port;
        this.secure = secure;

        String authTypeStr = config.getString(PROP_LDAPAUTHTYPE);

        if (authTypeStr.equals(LDAP_BASICAUTH_STR)) {
            mType = LDAP_AUTHTYPE_BASICAUTH;

        } else if (authTypeStr.equals(LDAP_SSLCLIENTAUTH_STR)) {
            mType = LDAP_AUTHTYPE_SSLCLIENTAUTH;

        } else {
            throw new IllegalArgumentException(
                    "Unknown Ldap authentication type " + authTypeStr);
        }
        mInited = true;
        logger.debug("LdapAuthInfo: init ends");
    }

    public String getBindDN() throws EBaseException {

        if (bindDN == null) {
            bindDN = config.getString(PROP_BINDDN);
        }

        return bindDN;
    }

    public String getBindPassword() throws EBaseException {

        // is the password found in memory?
        boolean inMem = false;

        // Passwords should only be written to the file for testing,
        // never in production
        String bindPassword = config.getString(PROP_BINDPW, null);

        // Next, see if this password has been requested before
        String prompt = config.getString(PROP_BINDPW_PROMPT, null);

        if (prompt == null) {
            prompt = "LDAP Authentication";
            logger.debug("LdapAuthInfo: init: prompt is null, change to " + prompt);
        } else {
            logger.debug("LdapAuthInfo: init: prompt is " + prompt);
        }

        if (bindPassword == null) {
            logger.debug("LdapAuthInfo: init: try getting from memory cache");
            bindPassword = passwords.get(prompt);
            if (bindPassword != null) {
                inMem = true;
                logger.debug("LdapAuthInfo: init: got password from memory");
            } else
                logger.debug("LdapAuthInfo: init: password not in memory");
        } else
            logger.debug("LdapAuthInfo: init: found password from config");

        if (bindPassword == null) {
            bindPassword = getPasswordFromStore(prompt);
        } else {
            logger.debug("LdapAuthInfo: init: password found for prompt.");
        }

        // verify the password
        if (bindPassword != null && !bindPassword.equals("") && (host == null ||
                authInfoOK(host, port, secure, bindDN, bindPassword))) {
            // The password is OK or uncheckable
            logger.debug("LdapAuthInfo: password ok: store in memory cache");
            passwords.put(prompt, bindPassword);

        } else {
            if (bindPassword == null) {
                logger.debug("LdapAuthInfo: password not found");
            } else {
                logger.debug("LdapAuthInfo: password does not work");
                /* what do you know?  Our IPasswordStore does not have a remove function.
                                pstore.remove("internaldb");
                */
                if (inMem) {
                    // this is for the case when admin changes pwd
                    // from console
                    bindPassword = getPasswordFromStore(prompt);
                    if (authInfoOK(host, port, secure, bindDN, bindPassword)) {
                        logger.debug("LdapAuthInfo: password ok: store in memory cache");
                        passwords.put(prompt, bindPassword);
                    }
                }
            }
        }

        return bindPassword;
    }

    public String getClientCertNickname() throws EBaseException {

        if (nickname == null) {
            nickname = config.getString(PROP_CLIENTCERTNICKNAME);
        }

        return nickname;
    }

    public void reset() {
        try {
            conn.disconnect();
        } catch (LDAPException e) {
        }
    }

    /**
     * Verifies the distinguished name and password by attempting to
     * authenticate to the server. If we connect to the server but cannot
     * authenticate, we conclude that the DN or password is invalid. If
     * we cannot connect at all, we don't know, so we return true
     * (there's no sense asking for the password again since we can't verify
     * it anyway). If we connect and authenticate successfully, we know
     * the DN and password are correct, so we return true.
     */
    private static LDAPConnection conn = new LDAPConnection();

    private static boolean
            authInfoOK(String host, int port, boolean secure, String dn, String pw) {

        // We dont perform auth checking if we are in SSL mode.
        if (secure)
            return true;

        boolean connected = false, authenticated = false;

        try {
            conn.connect(host, port);
            connected = true;
            conn.authenticate(dn, pw);
            authenticated = true;
        } catch (LDAPException e) {
        }

        /**
         * There is a bug in LDAP SDK. VM will crash on NT if
         * we connect and disconnect too many times.
         **/

        /**
         * if( connected ) {
         * try {
         * conn.disconnect();
         * } catch( LDAPException e ) { }
         * }
         **/

        if (connected && !authenticated) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * get authentication type.
     *
     * @return one of: <br>
     *         LdapAuthInfo.LDAP_AUTHTYPE_BASICAUTH or
     *         LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH
     */
    public int getAuthType() {
        return mType;
    }

    public IPasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(IPasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }

    /**
     * Add password to private password data structure.
     *
     * @param prompt Password prompt.
     * @param pw Password itself.
     */
    public void addPassword(String prompt, String pw) {
        passwords.put(prompt, pw);
    }

    /**
     * Remove password from private password data structure.
     *
     * @param prompt Identify password to remove with prompt.
     */
    public void removePassword(String prompt) {
        passwords.remove(prompt);
    }
}
