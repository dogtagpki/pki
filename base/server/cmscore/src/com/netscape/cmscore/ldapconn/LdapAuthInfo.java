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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

/**
 * class for reading ldap authentication info from config store
 */
public class LdapAuthInfo implements ILdapAuthInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapAuthInfo.class);

    protected int mType = -1;
    protected String[] mParms = null;

    private boolean mInited = false;

    private static Hashtable<String, String> passwords = new Hashtable<String, String>();

    /**
     * must call init(config) after this constructor.
     */
    public LdapAuthInfo() {
    }

    public String getPasswordFromStore(String prompt) throws EBaseException {
        String pwd = null;
        logger.debug("LdapAuthInfo: getPasswordFromStore: try to get it from password store");

        CMSEngine engine = CMS.getCMSEngine();

        // hey - should use password store interface to allow different implementations
        // but the problem is, other parts of the system just go directly to the file
        // so calling CMS.getPasswordStore() will give you an outdated one
        /*
                        IConfigStore mainConfig = CMS.getConfigStore();
                        String pwdFile = mainConfig.getString("passwordFile");
                        FileConfigStore pstore = new FileConfigStore(pwdFile);
        */
        IPasswordStore pwdStore = engine.getPasswordStore();
        logger.debug("LdapAuthInfo: getPasswordFromStore: about to get from passwored store: " + prompt);

        // support publishing dirsrv with different pwd than internaldb

        // Finally, interactively obtain the password from the user
        if (pwdStore != null) {
            logger.debug("LdapAuthInfo: getPasswordFromStore: password store available");
            pwd = pwdStore.getPassword(prompt, 0);
            //            pwd = pstore.getString(prompt);
            if (pwd == null) {
                logger.debug("LdapAuthInfo: getPasswordFromStore: password for " + prompt +
                        " not found, trying internaldb");

                //               pwd = pstore.getString("internaldb");

                pwd = pwdStore.getPassword("internaldb", 0); // last resort
            } else
                logger.debug("LdapAuthInfo: getPasswordFromStore: password found for prompt in password store");
        } else
            logger.debug("LdapAuthInfo: getPasswordFromStore: password store not available: pwdStore is null");

        return pwd;
    }

    /**
     * initialize this class from the config store.
     */
    public void init(IConfigStore config) throws EBaseException {
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
    public void init(IConfigStore config, String host, int port, boolean secure)
            throws EBaseException {

        logger.debug("LdapAuthInfo: init()");
        if (mInited) {
            logger.debug("LdapAuthInfo: already initialized");
            return; // XXX throw exception here ?
        }
        logger.debug("LdapAuthInfo: init begins");

        String authTypeStr = config.getString(PROP_LDAPAUTHTYPE);

        if (authTypeStr.equals(LDAP_BASICAUTH_STR)) {
            // is the password found in memory?
            boolean inMem = false;
            mType = LDAP_AUTHTYPE_BASICAUTH;
            mParms = new String[2];
            mParms[0] = config.getString(PROP_BINDDN);

            // Passwords should only be written to the file for testing,
            // never in production
            mParms[1] = config.getString(PROP_BINDPW, null);

            // Next, see if this password has been requested before
            String prompt = config.getString(PROP_BINDPW_PROMPT, null);

            if (prompt == null) {
                prompt = "LDAP Authentication";
                logger.debug("LdapAuthInfo: init: prompt is null, change to " + prompt);
            } else
                logger.debug("LdapAuthInfo: init: prompt is " + prompt);

            if (mParms[1] == null) {
                logger.debug("LdapAuthInfo: init: try getting from memory cache");
                mParms[1] = passwords.get(prompt);
                if (mParms[1] != null) {
                    inMem = true;
                    logger.debug("LdapAuthInfo: init: got password from memory");
                } else
                    logger.debug("LdapAuthInfo: init: password not in memory");
            } else
                logger.debug("LdapAuthInfo: init: found password from config");

            if (mParms[1] == null) {
                mParms[1] = getPasswordFromStore(prompt);
            } else {
                logger.debug("LdapAuthInfo: init: password found for prompt.");
            }

            // verify the password
            if ((mParms[1] != null) && (!mParms[1].equals("")) && (host == null ||
                    authInfoOK(host, port, secure, mParms[0], mParms[1]))) {
                // The password is OK or uncheckable
                logger.debug("LdapAuthInfo: password ok: store in memory cache");
                passwords.put(prompt, mParms[1]);
            } else {
                if (mParms[1] == null)
                    logger.debug("LdapAuthInfo: password not found");
                else {
                    logger.debug("LdapAuthInfo: password does not work");
                    /* what do you know?  Our IPasswordStore does not have a remove function.
                                    pstore.remove("internaldb");
                    */
                    if (inMem) {
                        // this is for the case when admin changes pwd
                        // from console
                        mParms[1] = getPasswordFromStore(prompt);
                        if (authInfoOK(host, port, secure, mParms[0], mParms[1])) {
                            logger.debug("LdapAuthInfo: password ok: store in memory cache");
                            passwords.put(prompt, mParms[1]);
                        }
                    }
                }
            }

        } else if (authTypeStr.equals(LDAP_SSLCLIENTAUTH_STR)) {
            mType = LDAP_AUTHTYPE_SSLCLIENTAUTH;
            mParms = new String[1];
            mParms[0] = config.getString(PROP_CLIENTCERTNICKNAME, null);
        } else {
            throw new IllegalArgumentException(
                    "Unknown Ldap authentication type " + authTypeStr);
        }
        mInited = true;
        logger.debug("LdapAuthInfo: init ends");
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

    /**
     * get params for authentication
     *
     * @return array of parameters for this authentication.
     */
    public String[] getParms() {
        return mParms.clone();
    }

    /**
     * add password
     */
    public void addPassword(String prompt, String pw) {
        try {
            passwords.put(prompt, pw);
        } catch (Exception e) {
        }
    }

    /**
     * remove password
     */
    public void removePassword(String prompt) {
        try {
            passwords.remove(prompt);
        } catch (Exception e) {
        }
    }
}
