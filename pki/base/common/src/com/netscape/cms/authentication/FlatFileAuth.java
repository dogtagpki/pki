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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.logging.ILogger;


/**
 * This represents the authentication manager that authenticates
 * user against a file where id, and password are stored.
 * 
 * @version $Revision$, $Date$
 */
public class FlatFileAuth 
    implements IProfileAuthenticator, IExtendedPluginInfo {

    /* configuration parameter keys */
    protected static final String PROP_FILENAME = "fileName";
    protected static final String PROP_KEYATTRIBUTES = "keyAttributes";
    protected static final String PROP_AUTHATTRS = "authAttributes";
    protected static final String PROP_DEFERONFAILURE = "deferOnFailure";

    protected String mFilename = "config/pwfile";
    protected long   mFileLastRead = 0;
    protected String mKeyAttributes = "UID";
    protected String mAuthAttrs = "PWD";
    protected boolean mDeferOnFailure = true;

    protected static String[] mConfigParams = 
        new String[] {
            PROP_FILENAME,
            PROP_KEYATTRIBUTES,
            PROP_AUTHATTRS,
            PROP_DEFERONFAILURE
        };

    public String[] getExtendedPluginInfo(Locale locale) {
        String s[] = {
                PROP_FILENAME + ";string;Pathname of password file",
                PROP_KEYATTRIBUTES + ";string;Comma-separated list of attributes" +
                " which together form a unique identifier for the user",
                PROP_AUTHATTRS + ";string;Comma-separated list of attributes" +
                " which are used for further authentication",
                PROP_DEFERONFAILURE + ";boolean;if user is not found, defer the " +
                "request to the queue for manual-authentication (true), or " +
                "simply rejected the request (false)"
            };

        return s;
    }
	
    /** name of this authentication manager instance */
    protected String mName = null;
	
    protected String FFAUTH = "FlatFileAuth";

    /** name of the authentication manager plugin */
    protected String mImplName = null;

    /** configuration store */
    protected IConfigStore mConfig = null;

    /** system logger */
    protected ILogger mLogger = CMS.getLogger();
	
    /** This array is created as to include all the requested attributes
     *
     */
    String[] reqCreds = null;

    String[] authAttrs = null;
    String[] keyAttrs = null;

    /** Hashtable of entries from Auth File. Hash index is the
     *  concatenation of the attributes from matchAttributes property
     */
    protected Hashtable entries = null;

    /**
     * Get the named property
     * If the property is not set, use s as the default, and create
     * a new value for the property in the config file.
     * 
     * @param propertyName Property name
     * @param s The default value of the property
     */
    protected String getPropertyS(String propertyName, String s)
        throws EBaseException {
        String p;

        try {
            p = mConfig.getString(propertyName);
        } catch (EPropertyNotFound e) {
            mConfig.put(propertyName, s);
            p = s;
        }
        return p;
    }

    public boolean isSSLClientRequired() {
        return false;
    }

    /**
     * Get the named property,
     * If the property is not set, use b as the default, and create
     * a new value for the property in the config file.
     * 
     * @param propertyName Property name
     * @param b The default value of the property
     */
    protected boolean getPropertyB(String propertyName, boolean b)
        throws EBaseException {
        boolean p;

        try {
            p = mConfig.getBoolean(propertyName);
        } catch (EPropertyNotFound e) {
            mConfig.put(propertyName, b ? "true" : "false");
            p = b;
        }
        return p;
    }

    public void init(String name, String implName, IConfigStore config)
        throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        try {
            mFilename = getPropertyS(PROP_FILENAME, mFilename);
            mKeyAttributes = getPropertyS(PROP_KEYATTRIBUTES, mKeyAttributes);
            mAuthAttrs = getPropertyS(PROP_AUTHATTRS, mAuthAttrs);
            mDeferOnFailure = getPropertyB(PROP_DEFERONFAILURE, mDeferOnFailure);
        } catch (EBaseException e) {
            return;
        }

        keyAttrs = splitOnComma(mKeyAttributes);
        authAttrs = splitOnComma(mAuthAttrs);

        String[][] stringArrays = new String[2][];

        stringArrays[0] = keyAttrs;
        stringArrays[1] = authAttrs;
        reqCreds = unionOfStrings(stringArrays);

        print("mFilename      = " + mFilename);
        print("mKeyAttributes = " + mKeyAttributes);
        print("mAuthAttrs     = " + mAuthAttrs);
        for (int i = 0; i < stringArrays.length; i++) {
            for (int j = 0; j < stringArrays[i].length; j++) {
                print("stringArrays[" + i + "][" + j + "] = " + stringArrays[i][j]);
            }
        }

        try {
            File file = new File(mFilename);

            mFileLastRead = file.lastModified();
            entries = readFile(file, keyAttrs);
            CMS.debug("FlatFileAuth: " + CMS.getLogMessage("CMS_AUTH_READ_ENTRIES", mFilename));
            // printAllEntries();
        } catch (IOException e) {
            throw new EBaseException(mName + " authentication: Could not open file " + mFilename + "   (" + e.getMessage() + ")");
        } catch (java.lang.StringIndexOutOfBoundsException ee) {
            CMS.debug("FlatFileAuth: " + CMS.getLogMessage("OPERATION_ERROR", ee.toString()));
        }

    }

    /**
     * Log a message.
     * @param level The logging level.
     * @param msg The message to log.
     */
    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHENTICATION,
            level, msg);
    }
 
    void print(String s) {
        CMS.debug("FlatFileAuth: " + s);
    }

    /**
     * Return a string array which is the union of all the string arrays
     * passed in. The strings are treated as case sensitive
     */

    public String[] unionOfStrings(String[][] stringArrays) {
        Hashtable ht = new Hashtable();

        for (int i = 0; i < stringArrays.length; i++) {
            String[] sa = stringArrays[i];

            for (int j = 0; j < sa.length; j++) {
                print("unionOfStrings: " + i + "," + j + " = " + sa[j]);
                ht.put(sa[j], "");
            }
        }

        String[] s = new String[ht.size()];
        Enumeration e = ht.keys();

        for (int i = 0; e.hasMoreElements(); i++) {
            s[i] = (String) e.nextElement();
        }
        return s;
		
    }
			
    /**
     * Split a comma-delimited String into an array of individual
     * Strings.
     */
    private String[] splitOnComma(String s) {
        print("Splitting String: " + s + " on commas");
        StringTokenizer st = new StringTokenizer(s, ",", false);
        String[] sa = new String[st.countTokens()];

        print("   countTokens:" + st.countTokens());

        for (int i = 0; i < sa.length; i++) {
            String p = st.nextToken().trim();

            print("   token " + i + " = " + p);
            sa[i] = p;
        }

        return sa;
    }

    /**
     * Join an array of Strings into one string, with
     * the specified string between each string
     */

    private String joinStringArray(String[] s, String sep) {

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < s.length; i++) {
            sb.append(s[i]);
            if (i < (s.length - 1)) {
                sb.append(sep);
            }
        }
        return sb.toString();
    }

    /**
     * Read a file with the following format: <p><pre>
     * param1: valuea
     * param2: valueb
     * -blank-line-
     * param1: valuec
     * param2: valued
     * </pre>
     *
     * @param f The file to read
     * @param keys The parameters to concat together to form the hash
     *   key
     * @return a hashtable of hashtables.
     */
    protected Hashtable readFile(File f, String[] keys)
        throws IOException {
        log(ILogger.LL_INFO, "Reading file: " + f.getName());
        BufferedReader file = new BufferedReader(
                new FileReader(f)
            );

        String line;
        Hashtable allusers = new Hashtable();
        Hashtable entry = null;
        int linenum = 0;

        while ((line = file.readLine()) != null) {
            linenum++;
            line = line.trim();
            if (line.length() > 0 && line.charAt(0) == '#') {
                continue;
            }
            int colon = line.indexOf(':');

            if (entry == null) {
                entry = new Hashtable();
            }

            if (colon == -1) {    // no colon -> empty line signifies end of record
                if (!line.trim().equals("")) {
                    if (file != null) {
                        file.close();
                    }
                    throw new IOException(FFAUTH + ": Parsing error, " +
                            "colon missing from line " + linenum + " of " + f.getName());
                }
                if (entry.size() > 0) {
                    putEntry(allusers, entry, keys);
                    entry = null;
                }
                continue;
            }

            String attr = line.substring(0, colon).trim();
            String val = line.substring(colon + 1).trim();

            entry.put(attr, val);
        }

        putEntry(allusers, entry, keys);
        if (file != null) {
            file.close();
        }
        return allusers;
    }

    private void putEntry(Hashtable allUsers,
        Hashtable entry, 
        String[] keys) {
        if (entry == null) {
            return;
        }
        String key = "";

        print("keys.length = " + keys.length);
        for (int i = 0; i < keys.length; i++) {
            String s = (String) entry.get(keys[i]);

            print(" concatenating: " + s);
            if (s != null) {
                key = key.concat(s);
            }
        }
        print("putting: key " + key);
        allUsers.put(key, entry);
    }

    void printAllEntries() {
        Enumeration e = entries.keys();

        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();

            print("* " + key + " *");
            Hashtable ht = (Hashtable) entries.get(key);
            Enumeration f = ht.keys();

            while (f.hasMoreElements()) {
                String fkey = (String) f.nextElement();

                print("   " + fkey + " -> " + ht.get(fkey));
            }
        }
    }

    /**
     * Compare attributes provided by the user with those in
     * in flat file.
     *
     */

    private IAuthToken doAuthentication(Hashtable user, IAuthCredentials authCred)
        throws EMissingCredential, EInvalidCredentials, EBaseException {
        AuthToken authToken = new AuthToken(this);

        for (int i = 0; i < authAttrs.length; i++) {
            String ffvalue = (String) user.get(authAttrs[i]);
            String uservalue = (String) authCred.get(authAttrs[i]);

            // print("checking authentication token (" + authAttrs[i] + ": " + uservalue + " against ff value: " + ffvalue);
            if (!ffvalue.equals(uservalue)) {
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
        }
        return authToken;
    }

    private void reReadPwFile() {

        try {
            File file = new File(mFilename);
            long pwfilelastmodified = file.lastModified();

            if (pwfilelastmodified > mFileLastRead) {
                mFileLastRead = pwfilelastmodified;
                entries = readFile(file, keyAttrs);
            }
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("READ_FILE_ERROR", mFilename, e.getMessage()));
        }
    }

    /**
     * Authenticate the request
     *
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
        throws EMissingCredential, EInvalidCredentials, EBaseException {
        IAuthToken authToken = null;
        String keyForUser = "";

        /* First check if hashtable has been modified since we last read it in */

        reReadPwFile();

        /* Find the user in our hashtable */

        for (int i = 0; i < keyAttrs.length; i++) {
            print("concatenating string i=" + i + "  keyAttrs[" + i + "] = " + keyAttrs[i]);
            String credential = (String) authCred.get(keyAttrs[i]);

            if (credential == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", keyAttrs[i]));
            }
            keyForUser = keyForUser.concat((String) authCred.get(keyAttrs[i]));
        }
        print("authenticating user: finding user from key: " + keyForUser);

        Hashtable user = (Hashtable) entries.get(keyForUser);

        try {
            if (user != null) {
                authToken = doAuthentication(user, authCred);
            } else {
                CMS.debug("FlatFileAuth: " + CMS.getLogMessage("CMS_AUTH_USER_NOT_FOUND"));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
        } catch (EInvalidCredentials e) {
            // If defer on failure is false, then we re-throw the exception
            // which causes the request to be rejected
            if (!mDeferOnFailure) {
                throw e;
            } else {
                CMS.debug("FlatFileAuth: Since defering on failure - ignore invalid creds");
            }
        }

        // if a dn was specified in the password file for this user, 
        // replace the requested dn with the one in the pwfile
        if (user != null) {
            String dn = (String) user.get("dn");

            if (dn != null) {
                authToken.set(AuthToken.TOKEN_CERT_SUBJECT, dn);
            }
        }

        // If defer on failure is true, and the auth failed, authToken will
        // be null here, which causes the request to be deferred.

        return authToken;
    }

    /**
     * Return a list of HTTP parameters which will be taken from the
     * request posting and placed into the AuthCredentials block
     *
     * Note that this method will not be called until after the
     * init() method is called
     */
    public String[] getRequiredCreds() {
        print("getRequiredCreds returning: " + joinStringArray(reqCreds, ","));
        return reqCreds;
	
    }

    /**
     * Returns a list of configuration parameters, so the console
     * can prompt the user when configuring.
     */
    public String[] getConfigParams() {
        return mConfigParams;
    }

    /**
     * Returns the configuration store used by this authentication manager
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void shutdown() {
    }

    public String getName() {
        return mName;
    }

    public String getImplName() {
        return mImplName;
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_NAME");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration getValueNames() {
        return null;
    }

    public boolean isValueWriteable(String name) {
        return false;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public void populate(IAuthToken token, IRequest request)
        throws EProfileException {
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_TEXT");
    }

}
