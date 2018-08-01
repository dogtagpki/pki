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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.authentication;

import java.math.BigInteger;
// ldap java sdk
import java.util.Enumeration;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.pkix.cmc.PKIData;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerValue;

/**
 * SharedSecret provides methods to retrieve shared secrets between users and
 * the server.  It is primarily developed to support CMC Shared Secret-based
 * authentication for enrollment and revocation, but does not
 * preclude usages that conform to the same mechanism and storage format.
 *
 * @author cfu
 *
 */
public class SharedSecret extends DirBasedAuthentication
        implements ISharedToken {
    /*
     * required credentials to authenticate. Though for this
     * special impl it will be unused.
     */
    public static final String CRED_ShrTok = "shrTok";
    protected static String[] mRequiredCreds = { CRED_ShrTok};

    protected static final String PROP_DNPATTERN = "dnpattern";
    protected static final String PROP_LDAPSTRINGATTRS = "ldapStringAttributes";
    protected static final String PROP_LDAPBYTEATTRS = "ldapByteAttributes";
    protected static final String PROP_LDAP_BOUND_CONN = "ldapBoundConn";
    protected static final String PROP_LDAP_BOUND_TAG = "ldapauth.bindPWPrompt";

    //public static final String PROP_REMOVE_SharedToken = "removeShrTok";
    public static final String PROP_SharedToken_ATTR = "shrTokAttr";

    //public static final boolean DEF_REMOVE_SharedToken = false;
    public static final String DEF_SharedToken_ATTR = "shrTok";
    public KeyWrapAlgorithm wrapAlgorithm = KeyWrapAlgorithm.RSA;

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] { //PROP_REMOVE_SharedToken,
                    PROP_SharedToken_ATTR,
                    PROP_DNPATTERN,
                    PROP_LDAPSTRINGATTRS,
                    PROP_LDAPBYTEATTRS,
                    "ldap.ldapconn.host",
                    "ldap.ldapconn.port",
                    "ldap.ldapconn.secureConn",
                    "ldap.ldapconn.version",
                    "ldap.ldapauth.bindDN",
                    "ldap.ldapauth.bindPWPrompt",
                    "ldap.ldapauth.clientCertNickname",
                    "ldap.ldapauth.authtype",
                    "ldap.basedn",
                    "ldap.minConns",
                    "ldap.maxConns",
        };

    static {
        //mExtendedPluginInfo.add(
                //PROP_REMOVE_SharedToken + ";boolean;SEE DOCUMENTATION for shared token removal");
        mExtendedPluginInfo.add(
                PROP_SharedToken_ATTR + ";string;directory attribute to use for pin (default 'pin')");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.bindDN;string;DN to bind. "
                        + "For example 'CN=SharedToken User'");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.bindPWPrompt;password;Enter password used to bind as " +
                        "the above user");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.clientCertNickname;string;If you want to use "
                        + "SSL client auth to the directory, set the client "
                        + "cert nickname here");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.authtype;choice(BasicAuth,SslClientAuth),required;"
                        + "How to bind to the directory (for pin removal only)");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TEXT
                + ";Authenticate the username, password and pin provided "
                + "by the user against an LDAP directory. Works with the "
                + "Dir/ShrTok Based Enrollment HTML form");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authrules-uidpwdpindirauth");

    }

    //protected boolean mRemoveShrTok = DEF_REMOVE_SharedToken;
    protected String mShrTokAttr = DEF_SharedToken_ATTR;
    private ILdapConnFactory shrTokLdapFactory = null;
    private IConfigStore shrTokLdapConfigStore = null;

    private PrivateKey issuanceProtPrivKey = null;
    protected CryptoToken token = null;
    protected byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
    EncryptionAlgorithm encryptAlgorithm = EncryptionAlgorithm.AES_128_CBC_PAD;
    ICertificateRepository certRepository = null;

    public SharedSecret() {
        super();
    }

    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        String method = "SharedSecret.init: ";
        String msg = "";
        CMS.debug(method + " begins.");
        super.init(name, implName, config);
        //TODO later:
        //mRemoveShrTok =
        //        config.getBoolean(PROP_REMOVE_SharedToken, DEF_REMOVE_SharedToken);
        mShrTokAttr =
                config.getString(PROP_SharedToken_ATTR, DEF_SharedToken_ATTR);
        if (mShrTokAttr == null) {
            msg = method + "shrTokAttr null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        if (mShrTokAttr.equals("")) {
            mShrTokAttr = DEF_SharedToken_ATTR;
        }

        initLdapConn(config);

        ICertificateAuthority authority =
                (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        issuanceProtPrivKey = authority.getIssuanceProtPrivKey();
        if (issuanceProtPrivKey != null)
            CMS.debug(method + "got issuanceProtPrivKey");
        else {
            msg = method + "issuanceProtPrivKey null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        certRepository = authority.getCertificateRepository();
        if (certRepository == null) {
            msg = method + "certRepository null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }

        try {
            String tokenName =
                    CMS.getConfigStore().getString("cmc.token", CryptoUtil.INTERNAL_TOKEN_NAME);
            CMS.debug(method + "getting token :" + tokenName);
            token = CryptoUtil.getKeyStorageToken(tokenName);
        } catch (Exception e) {
            CMS.debug(method + e);
            throw new EBaseException(e);
        }
        if (token == null) {
            msg = method + "token null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }

        CMS.debug(method + " ends.");
    }

    /**
     * initLadapConn initializes ldap connection for shared token based
     * CMC enrollment.
     */
    public void initLdapConn(IConfigStore config)
           throws EBaseException {
        String method = "SharedSecret.initLdapConn";
        String msg = "";

        shrTokLdapConfigStore = config.getSubStore("ldap");
        if (shrTokLdapConfigStore == null) {
            msg = method + "config substore ldap null";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        shrTokLdapFactory = CMS.getLdapBoundConnFactory("SharedSecret");
        if (shrTokLdapFactory == null) {
            msg = method + "CMS.getLdapBoundConnFactory returned null for SharedSecret";
            CMS.debug(msg);
            throw new EBaseException(msg);
        }
        shrTokLdapFactory.init(shrTokLdapConfigStore);
    }

    /**
     * getSharedToken(String identification, IAuthToken authToken) provides
     *  support for id_cmc_identification shared secret based enrollment
     *
     * @param identification maps to the uid in user's ldap record
     * @param authToken the IAuthToken that will be filled with the DN
     *        in user's ldap record
     *
     * Note: caller should clear the memory for the returned token
     *       after each use
     */
    public char[] getSharedToken(String identification, IAuthToken authToken)
            throws EBaseException {
        String method = "SharedSecret.getSharedToken(String identification, IAuthToken authToken): ";
        String msg = "";
        CMS.debug(method + "begins.");

        if ((identification == null) || (authToken == null)) {
            throw new EBaseException(method + "paramsters identification or authToken cannot be null");
        }
        LDAPConnection shrTokLdapConnection = null;
        LDAPSearchResults res = null;
        LDAPEntry entry = null;

        try {
            CMS.debug(method +
                    "searching for identification ="
                    + identification + "; mShrTokAttr =" + mShrTokAttr);
            // get shared token
            shrTokLdapConnection = shrTokLdapFactory.getConn();
            if (shrTokLdapConnection == null) {
                msg = method + "shrTokLdapConnection is null!!";
                CMS.debug(msg);
                throw new EBaseException(msg);
            }

            // get user dn.
            String userdn = null;
            res = shrTokLdapConnection.search(mBaseDN,
                    LDAPv2.SCOPE_SUB, "(uid=" + identification + ")", null, false);
            if (res == null) {
                msg = method + "shrTokLdapConnection.search returns null!!";
                CMS.debug(msg);
                throw new EBaseException(msg);
            }

            if (res.hasMoreElements()) {
                entry = (LDAPEntry) res.nextElement();

                userdn = entry.getDN();
            } else {
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_USER_NOT_EXIST", identification));
                msg = method + "ldap search result contains nothing";
                CMS.debug(msg);
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            if (userdn == null) {
                msg = method + "ldap entry found userdn null!!";
                CMS.debug(msg);
                throw new EBaseException(msg);
            }

            CMS.debug(method + "found user ldap entry: userdn = " + userdn);
            authToken.set(IAuthToken.TOKEN_CERT_SUBJECT, userdn);

            res = shrTokLdapConnection.search(userdn, LDAPv2.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mShrTokAttr }, false);
            if (res != null && res.hasMoreElements()) {
                entry = (LDAPEntry) res.nextElement();
            } else {
                msg = method + "no entry returned for " + identification;
                CMS.debug(msg);
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            LDAPAttribute shrTokAttr = entry.getAttribute(mShrTokAttr);

            if (shrTokAttr == null) {
                CMS.debug(method + "no shared token attribute found");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            @SuppressWarnings("unchecked")
            Enumeration<byte[]> shrTokValues = shrTokAttr.getByteValues();

            if (!shrTokValues.hasMoreElements()) {
                CMS.debug(method + "no shared token attribute values found");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            byte[] entryShrTok = shrTokValues.nextElement();
            if (entryShrTok == null) {
                CMS.debug(method + "no shared token value found");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            CMS.debug(method + " got entryShrTok");

            char[] shrSecret = decryptShrTokData(new String(entryShrTok));
            CMS.debug(method + "returning");
            return shrSecret;
        } catch (Exception e) {
            CMS.debug(method + " exception: " + e.toString());
            throw new EBaseException(method + e.toString());
        } finally {
            if (shrTokLdapConnection != null)
                shrTokLdapFactory.returnConn(shrTokLdapConnection);
        }
    }

    /**
     * decryptShrTokData decrypts data with the following format:
     * SEQUENCE {
     *     encryptedSession OCTET STRING,
     *     encryptedPrivate OCTET STRING
     * }
     * @param data_s
     * @return phrase in char array.
     */
    private char[] decryptShrTokData(String data_s) {
        String method = "SharedSecret.decryptShrTokData: ";
        byte[] ver_passphrase = null;
        try {
            byte[] wrapped_secret_data = Utils.base64decode(data_s);
            DerValue wrapped_val = new DerValue(wrapped_secret_data);
            // val.tag == DerValue.tag_Sequence
            DerInputStream wrapped_in = wrapped_val.data;
            DerValue wrapped_dSession = wrapped_in.getDerValue();
            byte wrapped_session[] = wrapped_dSession.getOctetString();
            CMS.debug(method + "wrapped session key retrieved");
            DerValue wrapped_dPassphrase = wrapped_in.getDerValue();
            byte wrapped_passphrase[] = wrapped_dPassphrase.getOctetString();
            CMS.debug(method + "wrapped passphrase retrieved");

            SymmetricKey ver_session = CryptoUtil.unwrap(token, SymmetricKey.AES, 128, SymmetricKey.Usage.UNWRAP,
                    issuanceProtPrivKey, wrapped_session, wrapAlgorithm);
            ver_passphrase = CryptoUtil.decryptUsingSymmetricKey(token, new IVParameterSpec(iv),
                    wrapped_passphrase,
                    ver_session, encryptAlgorithm);

            char[] ver_spassphraseChars = CryptoUtil.bytesToChars(ver_passphrase);
            return ver_spassphraseChars;
        } catch (Exception e) {
            CMS.debug(method + e.toString());
            return null;
        } finally {
            CryptoUtil.obscureBytes(ver_passphrase, "random");
        }
    }

    /**
     * unsupported
     */
    public char[] getSharedToken(PKIData cmcdata)
            throws EBaseException {
        String method = "SharedSecret.getSharedToken(PKIData cmcdata): ";
        String msg = "";
        throw new EBaseException(method + msg);
    }

    /**
     * getSharedToken(BigInteger serial) retrieves the shared secret data
     * from CA's internal certificate db based on serial number to revoke shared
     * secret based revocation
     * Note that unlike the shared token attribute for enrollment, the metaInfo
     * attribute for shared token in revocatoiin is not configurable.
     *
     * Note: caller should clear the memory for the returned token
     *       after each use
     */
    public char[] getSharedToken(BigInteger serial)
            throws EBaseException {
        String method = "SharedSecret.getSharedToken(BigInteger serial): ";
        String msg = "";

        if (serial == null) {
            throw new EBaseException(method + "paramster serial cannot be null");
        }
        CMS.debug(method + serial.toString());

        ICertRecord record = null;
        try {
            record = certRepository.readCertificateRecord(serial);
        } catch (EBaseException ee) {
            CMS.debug(method + "Exception: " + ee.toString());
            msg = method + "cert record not found";
            CMS.debug(msg);
            throw ee;
        }

        MetaInfo metaInfo = (MetaInfo) record.get(ICertRecord.ATTR_META_INFO);
        if (metaInfo == null) {
            msg = "cert record metaInfo not found";
            CMS.debug(method + msg);
            throw new EBaseException(method + msg);
        }
        String shrTok_s = (String) metaInfo.get(ICertRecord.META_REV_SHRTOK);
        if (shrTok_s == null) {
            msg = "shrTok not found in metaInfo";
            CMS.debug(method + msg);
            throw new EBaseException(method + msg);
        }

        char[] shrSecret = decryptShrTokData(shrTok_s);
        CMS.debug(method + "returning");
        return shrSecret;
    }

    /**
     * unsupported
     * This is an unconventional authentication plugin implementation that
     * does not support authenticate()
     */
    protected String authenticate(LDAPConnection conn,
            IAuthCredentials authCreds,
            AuthToken token)
            throws EBaseException {
        String method = "SharedSecret:authenticate: ";
        //unused
        throw new EBaseException(method + " unsupported to be called this way.");
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
