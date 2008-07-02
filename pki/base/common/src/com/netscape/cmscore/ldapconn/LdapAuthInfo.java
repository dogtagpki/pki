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
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;
import org.mozilla.jss.util.ConsolePasswordCallback;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.cmscore.base.*;


/**
 * class for reading ldap authentication info from config store
 */
public class LdapAuthInfo implements ILdapAuthInfo {

    protected int mType = -1;
    protected String[] mParms = null;

    private boolean mInited = false;

    private static Hashtable passwords = new Hashtable();

    /**
     * must call init(config) after this constructor.
     */
    public LdapAuthInfo() {
    }

    /**
     * constructs ldap auth info directly from config store.
     */
    public LdapAuthInfo(IConfigStore config) throws EBaseException {
        init(config);
    }

    /**
     * constructs ldap auth info directly from config store, and verifies
     * the password by attempting to connect to the server.
     */
    public LdapAuthInfo(IConfigStore config, String host, int port, boolean secure)
        throws EBaseException {
        init(config, host, port, secure);
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
     *      This will be used to verify the password by attempting to connect.
     *      If it is <code>null</code>, the password will not be verified.
     * @param port The port that the directory server is running on.
     */
    public void init(IConfigStore config, String host, int port, boolean secure)
        throws EBaseException {
        if (mInited) 
            return;			// XXX throw exception here ?

        String authTypeStr = config.getString(PROP_LDAPAUTHTYPE);

        if (authTypeStr.equals(LDAP_BASICAUTH_STR)) {
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
            }
            if (mParms[1] == null) {
                mParms[1] = (String) passwords.get(prompt);
            }

            // Finally, interactively obtain the password from the user
            if (mParms[1] == null) {
                IConfigStore mainConfig = CMS.getConfigStore();
                String pwdFile = mainConfig.getString("passwordFile");
                FileConfigStore pstore = new FileConfigStore(pwdFile);
                mParms[1] = pstore.getString("internaldb");

                // verify the password
                if ((!mParms[1].equals("")) && (host == null ||
                  authInfoOK(host, port, secure, mParms[0], mParms[1]))) {
                    // The password is OK or uncheckable
                    passwords.put(prompt, mParms[1]);
                } else {
                    pstore.remove("internaldb");
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
    }

    public void reset() {
        try {
            conn.disconnect();
        } catch (LDAPException e) {
        }
    }

    /**
     * Verifies the distinguished name and password by attempting to
     * authenticate to the server.  If we connect to the server but cannot
     * authenticate, we conclude that the DN or password is invalid. If
     * we cannot connect at all, we don't know, so we return true
     * (there's no sense asking for the password again since we can't verify
     * it anyway).  If we connect and authenticate successfully, we know
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
         if( connected ) {
         try {
         conn.disconnect();
         } catch( LDAPException e ) { }
         }
         **/

        if (connected && !authenticated) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * get authentication type. 
     * @return one of: <br>
     *		LdapAuthInfo.LDAP_AUTHTYPE_BASICAUTH or 
     *		LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH
     */
    public int getAuthType() {
        return mType;
    }

    /**
     * get params for authentication
     * @return array of parameters for this authentication.
     */
    public String[] getParms() {
        return (String[]) mParms.clone();
    }

    /**
     * add password
     */
    public void addPassword(String prompt, String pw) {
        try {
            passwords.put(prompt, pw);
        }catch (Exception e) {
        }
    }

    /**
     * remove password
     */
    public void removePassword(String prompt) {
        try {
            passwords.remove(prompt);
        }catch (Exception e) {
        }
    }
}
