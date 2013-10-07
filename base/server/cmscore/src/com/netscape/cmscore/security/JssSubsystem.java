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
package com.netscape.cmscore.security;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.util.DN;
import netscape.security.x509.AlgIdDSA;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NicknameConflictException;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.CryptoManager.UserCertConflictException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11SecureRandom;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkcs7.SignedData;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.security.ICryptoSubsystem;
import com.netscape.certsrv.security.KeyCertData;
import com.netscape.cmscore.cert.CertPrettyPrint;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * Subsystem for initializing JSS>
 * <P>
 *
 * @version $Revision$ $Date$
 */
public final class JssSubsystem implements ICryptoSubsystem {
    public static final String ID = "jss";

    private static final String CONFIG_DIR = "configDir";
    private static final String PROP_ENABLE = "enable";
    private static final String PASSWORD_ALIAS = "password";
    private static final String mId = ID;
    protected IConfigStore mConfig = null;
    private boolean mInited = false;
    private ILogger mLogger = null;
    private CryptoManager mCryptoManager = null;

    protected PasswordCallback mPWCB = null;

    private static JssSubsystem mInstance = new JssSubsystem();
    private Hashtable<String, X509Certificate[]> mNicknameMapCertsTable = new Hashtable<String, X509Certificate[]>();
    private Hashtable<String, X509Certificate[]> mNicknameMapUserCertsTable =
            new Hashtable<String, X509Certificate[]>();

    private FileInputStream devRandomInputStream = null;

    // This date format is to format the date string of the certificate in such a way as
    // May 01, 1999 01:55:55.
    private static SimpleDateFormat mFormatter = new SimpleDateFormat("MMMMM dd, yyyy HH:mm:ss");

    // SSL related variables.

    private IConfigStore mSSLConfig = null;

    private static final String PROP_SSL = "ssl";
    private static final String PROP_SSL_CIPHERPREF = Constants.PR_CIPHER_PREF;
    private static final String PROP_SSL_ECTYPE = Constants.PR_ECTYPE;

    private static Hashtable<String, Integer> mCipherNames = new Hashtable<String, Integer>();

    /* default sslv2 and sslv3 cipher suites(all), set if no prefs in config.*/
    private static final String DEFAULT_CIPHERPREF =
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA," +
                    "TLS_RSA_WITH_AES_128_CBC_SHA," +
                    "TLS_RSA_WITH_AES_256_CBC_SHA," +
                    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA," +
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA," +
                    //        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA," +
                    //        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA," +
                    //        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA," +
                    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA," +
                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA," +
                    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA," +
                    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";

    /* list of all ciphers JSS supports */
    private static final int mJSSCipherSuites[] = {
            SSLSocket.SSL2_RC4_128_WITH_MD5,
            SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5,
            SSLSocket.SSL2_RC2_128_CBC_WITH_MD5,
            SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5,
            SSLSocket.SSL2_DES_64_CBC_WITH_MD5,
            SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5,
            SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
            SSLSocket.SSL3_RSA_WITH_RC4_128_MD5,
            SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
            SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA,
            SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
            SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,
            SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA,
            SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
            SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
        };

    static {

        /* set ssl cipher string names. */
        /* disallowing SSL2 ciphers to be turned on
        mCipherNames.put(Constants.PR_SSL2_RC4_128_WITH_MD5,
            Integer.valueOf(SSLSocket.SSL2_RC4_128_WITH_MD5));
        mCipherNames.put(Constants.PR_SSL2_RC4_128_EXPORT40_WITH_MD5,
            Integer.valueOf(SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5));
        mCipherNames.put(Constants.PR_SSL2_RC2_128_CBC_WITH_MD5,
            Integer.valueOf(SSLSocket.SSL2_RC2_128_CBC_WITH_MD5));
        mCipherNames.put(Constants.PR_SSL2_RC2_128_CBC_EXPORT40_WITH_MD5,
            Integer.valueOf(SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5));
        mCipherNames.put(Constants.PR_SSL2_DES_64_CBC_WITH_MD5,
            Integer.valueOf(SSLSocket.SSL2_DES_64_CBC_WITH_MD5));
        mCipherNames.put(Constants.PR_SSL2_DES_192_EDE3_CBC_WITH_MD5,
            Integer.valueOf(SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5));
        */
        mCipherNames.put(Constants.PR_SSL3_RSA_WITH_NULL_MD5,
                Integer.valueOf(SSLSocket.SSL3_RSA_WITH_NULL_MD5));
        mCipherNames.put(Constants.PR_SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
                Integer.valueOf(SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5));
        mCipherNames.put(Constants.PR_SSL3_RSA_WITH_RC4_128_MD5,
                Integer.valueOf(SSLSocket.SSL3_RSA_WITH_RC4_128_MD5));
        mCipherNames.put(Constants.PR_SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
                Integer.valueOf(SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5));
        mCipherNames.put(Constants.PR_SSL3_RSA_WITH_DES_CBC_SHA,
                Integer.valueOf(SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA));
        mCipherNames.put(Constants.PR_SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
                Integer.valueOf(SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA));
        mCipherNames.put(Constants.PR_SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,
                Integer.valueOf(SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA));
        mCipherNames.put(Constants.PR_SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA,
                Integer.valueOf(SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA));
        mCipherNames.put(Constants.PR_SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA,
                Integer.valueOf(SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA));
        mCipherNames.put(Constants.PR_SSL_RSA_FIPS_WITH_DES_CBC_SHA,
                Integer.valueOf(SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA));
        mCipherNames.put(Constants.PR_TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
                Integer.valueOf(SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA));
        mCipherNames.put(Constants.PR_TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                Integer.valueOf(SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA));
    }

    public static JssSubsystem getInstance() {
        return mInstance;
    }

    /**
     * Constructs a Security service subsystem.
     */
    private JssSubsystem() {
    }

    public String getId() {
        return mId;
    }

    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));

    }

    // Add entropy to the 'default' RNG token
    public void addEntropy(int bits)
            throws org.mozilla.jss.util.NotImplementedException,
            IOException,
            TokenException {
        int read = 0;
        int bytes = (7 + bits) / 8;
        byte[] b = new byte[bytes];
        if (devRandomInputStream == null) {
            throw new IOException(CMS.getLogMessage("CMSCORE_SECURITY_NO_ENTROPY_STREAM"));
        }
        do {
            int c = devRandomInputStream.read(b, read, bytes - read);
            read += c;
        } while (read < bytes);

        CMS.debug("JssSubsystem adding " + bits + " bits (" + bytes + " bytes) of entropy to default RNG token");
        CMS.debug(b);
        PK11SecureRandom sr = new PK11SecureRandom();
        sr.setSeed(b);
    }

    /**
     * Initializes the Jss security subsystem.
     * <P>
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mLogger = CMS.getLogger();

        if (mInited) {
            // This used to throw an exeception (e.g. - on Solaris).
            // If JSS is already initialized simply return.
            CMS.debug("JssSubsystem already inited.. returning.");
            return;
        }

        mConfig = config;

        // If disabled, just return
        boolean enabled = config.getBoolean(PROP_ENABLE, true);

        if (!enabled)
            return;

        try {
            devRandomInputStream = new FileInputStream("/dev/urandom");
        } catch (IOException ioe) {
            // XXX - add new exception
        }

        // get hardcoded password (for debugging.
        String pw;

        if ((pw = config.getString(PASSWORD_ALIAS, null)) != null) {
            // hardcoded password in config file
            mPWCB = new Password(pw.toCharArray());
            CMS.debug("JssSubsystem init() got password from hardcoded in config");
        }

        String certDir;

        certDir = config.getString(CONFIG_DIR, null);

        CryptoManager.InitializationValues vals = new CryptoManager.InitializationValues(certDir, "", "", "secmod.db");

        vals.removeSunProvider = false;
        vals.installJSSProvider = true;
        try {
            CryptoManager.initialize(vals);
        } catch (AlreadyInitializedException e) {
            // do nothing
        } catch (Exception e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }

        try {
            mCryptoManager = CryptoManager.getInstance();
            initSSL();
        } catch (CryptoManager.NotInitializedException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }

        mInited = true;
    }

    public String getCipherVersion() throws EBaseException {
        return "cipherdomestic";
    }

    public String getCipherPreferences() throws EBaseException {
        String cipherpref = "";

        if (mSSLConfig != null) {
            cipherpref = mSSLConfig.getString(PROP_SSL_CIPHERPREF, "");
            if (cipherpref.equals("")) {
                cipherpref = DEFAULT_CIPHERPREF;
            }
        }
        return cipherpref;
    }

    public String getECType(String certType) throws EBaseException {
        if (mSSLConfig != null) {
            // for SSL server, check the value of jss.ssl.sslserver.ectype
            return mSSLConfig.getString(certType + "." + PROP_SSL_ECTYPE, "ECDHE");
        } else {
            return "ECDHE";
        }
    }

    public String isCipherFortezza() throws EBaseException {
        // we always display fortezza suites.
        // too much work to display tokens/certs corresponding to the
        // suites.
        return "true";
    }

    void installProvider() {
        int position = java.security.Security.insertProviderAt(
                new com.netscape.cmscore.security.Provider(),
                1);

        if (position == -1) {
            Debug.trace("Unable to install CMS provider");
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_SECURITY_INSTALL_PROVIDER"));
        }
    }

    public void setCipherPreferences(String cipherPrefs)
            throws EBaseException {
        if (mSSLConfig != null) {
            if (cipherPrefs.equals(""))
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_EMPTY_CIPHERPREFS"));
            mSSLConfig.putString(Constants.PR_CIPHER_PREF, cipherPrefs);
        }
    }

    /**
     * Initialize SSL cipher suites from config file.
     *
     */
    private void initSSL() throws EBaseException {
        // JSS will AND what is set and what is allowed by export policy
        // so we can set what is requested.

        try {
            SSLServerSocket.configServerSessionIDCache(10, 0, 0, null);
        } catch (SocketException e) {
        }

        mSSLConfig = mConfig.getSubStore(PROP_SSL);
        String sslCiphers = null;

        if (mSSLConfig != null)
            sslCiphers = getCipherPreferences();
        if (Debug.ON)
            Debug.trace("configured ssl cipher prefs is " + sslCiphers);

        // first, disable all ciphers, since JSS defaults to all-enabled
        for (int i = mJSSCipherSuites.length - 1; i >= 0; i--) {
            try {
                SSLSocket.setCipherPreferenceDefault(mJSSCipherSuites[i],
                        false);
            } catch (SocketException e) {
            }
        }

        // the sslCiphers string will always contain something

        if (sslCiphers != null && sslCiphers.length() != 0) {
            StringTokenizer ciphers = new StringTokenizer(sslCiphers, ",");

            if (!ciphers.hasMoreTokens()) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_SECURITY_INVALID_CIPHER", sslCiphers));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY", PROP_SSL_CIPHERPREF));
            }
            while (ciphers.hasMoreTokens()) {
                String cipher = ciphers.nextToken();
                Integer sslcipher = mCipherNames.get(cipher);

                if (sslcipher != null) {
                    String msg = "setting ssl cipher " + cipher;

                    CMS.debug("JSSSubsystem: initSSL(): " + msg);
                    log(ILogger.LL_INFO, msg);
                    if (Debug.ON)
                        Debug.trace(msg);
                    try {
                        SSLSocket.setCipherPreferenceDefault(
                                sslcipher.intValue(), true);
                    } catch (SocketException e) {
                    }
                }
            }
        }

    }

    /**
     * Retrieves a configuration store of this subsystem.
     * <P>
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Starts up this service.
     */
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem.
     * <P>
     */
    public void shutdown() {
        try {
            // After talking to NSS teamm, we should not call close databases
            // which will call NSS_Shutdown. Web Server will call NSS_Shutdown
            boolean isClosing = mConfig.getBoolean("closeDatabases", false);
            if (isClosing) {
                JSSDatabaseCloser closer = new JSSDatabaseCloser();
                closer.closeDatabases();
            }
        } catch (Exception e) {
        }
    }

    public void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, level, "JSS " + msg);
    }

    public PasswordCallback getPWCB() {
        return mPWCB;
    }

    public String getInternalTokenName() throws EBaseException {
        CryptoToken c = mCryptoManager.getInternalKeyStorageToken();
        String name = "";

        try {
            name = c.getName();
        } catch (TokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }

        return name;
    }

    public String getTokenList() throws EBaseException {
        StringBuffer tokenList = new StringBuffer();

        @SuppressWarnings("unchecked")
        Enumeration<CryptoToken> tokens = mCryptoManager.getExternalTokens();
        int num = 0;

        try {
            while (tokens.hasMoreElements()) {
                CryptoToken c = tokens.nextElement();

                // skip builtin object token
                if (c.getName() != null && c.getName().equals("Builtin Object Token")) {
                    continue;
                }

                if (num++ != 0)
                    tokenList.append(",");
                tokenList.append(c.getName());
            }
        } catch (TokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }

        if (tokenList.length()==0)
            return Constants.PR_INTERNAL_TOKEN;
        else
            return tokenList.append("," + Constants.PR_INTERNAL_TOKEN).toString();
    }

    public boolean isTokenLoggedIn(String name) throws EBaseException {
        try {
            if (name.equals(Constants.PR_INTERNAL_TOKEN_NAME))
                name = Constants.PR_FULL_INTERNAL_TOKEN_NAME;
            CryptoToken ctoken = mCryptoManager.getTokenByName(name);

            return ctoken.isLoggedIn();
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (NoSuchTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        }
    }

    public void loggedInToken(String tokenName, String pwd) throws EBaseException {
        try {
            CryptoToken ctoken = mCryptoManager.getTokenByName(tokenName);
            Password clk = new Password(pwd.toCharArray());

            ctoken.login(clk);
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (IncorrectPasswordException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_LOGIN_FAILED"));
        } catch (NoSuchTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        }
    }

    public String getCertSubjectName(String tokenname, String nickname)
            throws EBaseException {
        try {
            return KeyCertUtil.getCertSubjectName(tokenname, nickname);
        } catch (NoSuchTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    public String getAllCerts() throws EBaseException {
        StringBuffer certNames = new StringBuffer();

        try {
            @SuppressWarnings("unchecked")
            Enumeration<CryptoToken> enums = mCryptoManager.getAllTokens();

            while (enums.hasMoreElements()) {
                CryptoToken token = enums.nextElement();
                CryptoStore store = token.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                for (int i = 0; i < list.length; i++) {
                    String nickname = list[i].getNickname();

                    if (certNames.length() < 1) {
                        certNames.append(nickname);
                    } else {
                        certNames.append("," + nickname);
                    }
                }
            }
        } catch (TokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }

        return certNames.toString();
    }

    public String getCertListWithoutTokenName(String name) throws EBaseException {

        CryptoToken c = null;
        StringBuffer certNames = new StringBuffer();

        try {
            if (name.equals(Constants.PR_INTERNAL_TOKEN)) {
                c = mCryptoManager.getInternalKeyStorageToken();
            } else {
                c = mCryptoManager.getTokenByName(name);
            }

            if (c != null) {
                CryptoStore store = c.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                if (list == null)
                    return "";

                for (int i = 0; i < list.length; i++) {
                    String nickname = list[i].getNickname();
                    int index = nickname.indexOf(":");

                    if (index != -1)
                        nickname = nickname.substring(index + 1);
                    if (i != 0)
                        certNames.append(",");
                    certNames.append(nickname);
                }
                return certNames.toString();
            } else
                return "";

        } catch (TokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        } catch (NoSuchTokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }
    }

    public String getCertList(String name) throws EBaseException {

        CryptoToken c = null;
        StringBuffer certNames = new StringBuffer();

        try {
            if (name.equals(Constants.PR_INTERNAL_TOKEN)) {
                c = mCryptoManager.getInternalKeyStorageToken();
            } else {
                c = mCryptoManager.getTokenByName(name);
            }

            if (c != null) {
                CryptoStore store = c.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                if (list == null)
                    return "";

                for (int i = 0; i < list.length; i++) {
                    String nickname = list[i].getNickname();

                    if (i != 0)
                        certNames.append(",");
                    certNames.append(nickname);
                }

                return certNames.toString();
            } else
                return "";

        } catch (TokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        } catch (NoSuchTokenException e) {
            String[] params = { mId, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()));
            throw ex;
        }
    }

    public AlgorithmId getAlgorithmId(String algname, IConfigStore store)
            throws EBaseException {
        try {
            if (algname.equals("DSA")) {
                byte[] p = store.getByteArray("ca.dsaP", null);
                byte[] q = store.getByteArray("ca.dsaQ", null);
                byte[] g = store.getByteArray("ca.dsaG", null);

                if (p != null && q != null && g != null) {
                    BigInteger P = new BigInteger(p);
                    BigInteger Q = new BigInteger(q);
                    BigInteger G = new BigInteger(g);

                    return new AlgIdDSA(P, Q, G);
                }
            }
            return AlgorithmId.get(algname);
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", ""));
        }
    }

    public String getSignatureAlgorithm(String nickname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            X509CertImpl impl = new X509CertImpl(cert.getEncoded());

            return impl.getSigAlgName();
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (ObjectNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    public KeyPair getKeyPair(String nickname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            PrivateKey priKey = CryptoManager.getInstance().findPrivKeyByCert(cert);
            PublicKey publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, priKey);
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, "Key Pair Error " + e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (ObjectNotFoundException e) {
            log(ILogger.LL_FAILURE, "Key Pair Error " + e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, "Key Pair Error " + e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        }
    }

    public KeyPair getKeyPair(String tokenName, String alg,
            int keySize) throws EBaseException {
        return getKeyPair(tokenName, alg, keySize, null);
    }

    public KeyPair getKeyPair(String tokenName, String alg,
            int keySize, PQGParams pqg) throws EBaseException {

        String t = tokenName;
        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN))
            t = Constants.PR_FULL_INTERNAL_TOKEN_NAME;
        CryptoToken token = null;

        try {
            token = mCryptoManager.getTokenByName(t);
        } catch (NoSuchTokenException e) {
            log(ILogger.LL_FAILURE, "Generate Key Pair Error " + e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", tokenName));
        }

        KeyPairAlgorithm kpAlg = null;

        if (alg.equals("RSA"))
            kpAlg = KeyPairAlgorithm.RSA;
        else {
            kpAlg = KeyPairAlgorithm.DSA;
        }

        try {
            KeyPair kp = KeyCertUtil.generateKeyPair(token, kpAlg, keySize, pqg);
            return kp;
        } catch (InvalidParameterException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEYSIZE_PARAMS",
                        "" + keySize));
        } catch (PQGParamGenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED",
                        kpAlg.toString()));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_KEY_GEN_FAILED"));
        } catch (InvalidAlgorithmParameterException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", "DSA"));
        }
    }

    public void isX500DN(String dn) throws EBaseException {
        try {
            new X500Name(dn); // check for errors
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_X500_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_X500_NAME", dn));
        }
    }

    public String getCertRequest(String subjectName, KeyPair kp)
            throws EBaseException {
        try {
            netscape.security.pkcs.PKCS10 pkcs = KeyCertUtil.getCertRequest(subjectName, kp);
            ByteArrayOutputStream bs = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(bs);
            pkcs.print(ps);
            return bs.toString();
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", ""));
        } catch (NoSuchProviderException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PROVIDER_NOT_SUPPORTED"));
        } catch (InvalidKeyException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_REQ_FAILED"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_CERT", e.toString()));
        } catch (SignatureException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_SIGNATURE"));
        }
    }

    public void importCert(String b64E, String nickname, String certType)
            throws EBaseException {
        try {
            KeyCertUtil.importCert(b64E, nickname, certType);
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            String eString = e.toString();
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            if (eString.contains("Failed to find certificate that was just imported")) {
                throw new EBaseException(eString);
            } else {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
            }
        } catch (UserCertConflictException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_USERCERT_CONFLICT"));
        } catch (NicknameConflictException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NICKNAME_CONFLICT"));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        }
    }

    public KeyPair getKeyPair(KeyCertData properties) throws EBaseException {
        String tokenname = Constants.PR_INTERNAL_TOKEN_NAME;
        String keyType = "RSA";
        int keyLength = 512;

        String tmp = (String) properties.get(Constants.PR_TOKEN_NAME);

        if ((tmp != null) &&
                (!tmp.equals(Constants.PR_INTERNAL_TOKEN)))
            tokenname = tmp;
        tmp = (String) properties.get(Constants.PR_KEY_TYPE);
        if (tmp != null)
            keyType = tmp;
        tmp = (String) properties.get(Constants.PR_KEY_LENGTH);
        if (tmp != null)
            keyLength = Integer.parseInt(tmp);

        KeyPair pair = getKeyPair(tokenname, keyType, keyLength);

        return pair;
    }

    public KeyPair getECCKeyPair(KeyCertData properties) throws EBaseException {
        String token = Constants.PR_INTERNAL_TOKEN_NAME;
        String keyCurve = "nistp512";
        String certType = null;
        KeyPair pair = null;

        String tmp = (String) properties.get(Constants.PR_TOKEN_NAME);
        if (tmp != null)
            token = tmp;

        tmp = (String) properties.get(Constants.PR_KEY_CURVENAME);
        if (tmp != null)
            keyCurve = tmp;

        certType = (String) properties.get(Constants.RS_ID);

        pair = getECCKeyPair(token, keyCurve, certType);

        return pair;
    }

    public KeyPair getECCKeyPair(String token, String keyCurve, String certType) throws EBaseException {
        KeyPair pair = null;

        if ((token == null) || (token.equals("")))
            token = Constants.PR_INTERNAL_TOKEN_NAME;

        if ((keyCurve == null) || (keyCurve.equals("")))
            keyCurve = "nistp512";

        String ectype = getECType(certType);

        // ECDHE needs "SIGN" but no "DERIVE"
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask[] = {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
        };

        // ECDH needs "DERIVE" but no any kind of "SIGN"
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage ECDH_usages_mask[] = {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER,
        };

        try {
            if (ectype.equals("ECDHE"))
                pair = CryptoUtil.generateECCKeyPair(token, keyCurve, null, usages_mask);
            else
                pair = CryptoUtil.generateECCKeyPair(token, keyCurve, null, ECDH_usages_mask);
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (NoSuchTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_SUCH_ALGORITHM", e.toString()));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        }

        return pair;
    }

    public void importCert(X509CertImpl signedCert, String nickname,
            String certType) throws EBaseException {

        try {
            KeyCertUtil.importCert(signedCert, nickname, certType);
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ENCODE_CERT_FAILED"));
        } catch (UserCertConflictException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_USERCERT_CONFLICT"));
        } catch (NicknameConflictException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NICKNAME_CONFLICT"));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ENCODE_CERT_FAILED"));
        }
    }

    public NameValuePairs getCertInfo(String b64E) throws EBaseException {
        try {
            byte[] b = KeyCertUtil.convertB64EToByteArray(b64E);
            X509CertImpl impl = new X509CertImpl(b);
            NameValuePairs results = new NameValuePairs();

            results.put(Constants.PR_CERT_SUBJECT_NAME, impl.getSubjectDN().getName());
            results.put(Constants.PR_ISSUER_NAME, impl.getIssuerDN().getName());
            results.put(Constants.PR_SERIAL_NUMBER, impl.getSerialNumber().toString());
            results.put(Constants.PR_BEFORE_VALIDDATE, impl.getNotBefore().toString());
            results.put(Constants.PR_AFTER_VALIDDATE, impl.getNotAfter().toString());

            // fingerprint is using MD5 hash

            return results;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_INFO", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_CERT_INFO", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        }
    }

    public void deleteUserCert(String nickname, String serialno, String issuername)
            throws EBaseException {
        try {
            X509Certificate cert = getCertificate(nickname, serialno, issuername);
            if (cert instanceof TokenCertificate) {
                TokenCertificate tcert = (TokenCertificate) cert;

                CMS.debug("*** deleting this token cert");
                tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                CMS.debug("*** finish deleting this token cert");
            } else {
                CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                CryptoStore store = token.getCryptoStore();

                CMS.debug("*** deleting this interna cert");
                store.deleteCert(cert);
                CMS.debug("*** removing this interna cert");
            }
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        }
    }

    public void deleteRootCert(String nickname, String serialno,
            String issuername) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            if (mNicknameMapCertsTable != null) {
                X509Certificate[] certs = mNicknameMapCertsTable.get(nickname);

                if (certs == null) {
                    EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CA_CERT", e.toString()));
                    throw e;
                } else {
                    for (int i = 0; i < certs.length; i++) {
                        X509Certificate cert = certs[i];
                        X509CertImpl impl = new X509CertImpl(cert.getEncoded());
                        String num = impl.getSerialNumber().toString();
                        String issuer = impl.getIssuerDN().toString();
                        CMS.debug("*** num " + num);
                        CMS.debug("*** issuer " + issuer);
                        if (num.equals(serialno) && issuername.equals(issuer)) {
                            CMS.debug("*** removing root cert");
                            if (cert instanceof TokenCertificate) {
                                TokenCertificate tcert = (TokenCertificate) cert;

                                CMS.debug("*** deleting this token cert");
                                tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                                CMS.debug("*** finish deleting this token cert");
                            } else {
                                CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                                CryptoStore store = token.getCryptoStore();

                                CMS.debug("*** deleting this interna cert");
                                store.deleteCert(cert);
                                CMS.debug("*** removing this interna cert");
                            }
                            mNicknameMapCertsTable.remove(nickname);
                            break;
                        }
                    }
                }
            }

        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public NameValuePairs getRootCerts() throws EBaseException {
        NameValuePairs nvps = new NameValuePairs();
        try {
            @SuppressWarnings("unchecked")
            Enumeration<CryptoToken> enums = mCryptoManager.getAllTokens();
            if (mNicknameMapCertsTable != null) {
                mNicknameMapCertsTable.clear();
            } else {
                CMS.debug("JssSubsystem::getRootCerts() - mNicknameMapCertsTable is null");
                throw new EBaseException("JssSubsystem::getRootCerts() - mNicknameMapCertsTable is null");
            }

            // a temp hashtable with vectors
            Hashtable<String, Vector<X509Certificate>> vecTable = new Hashtable<String, Vector<X509Certificate>>();

            while (enums.hasMoreElements()) {
                CryptoToken token = enums.nextElement();
                String tokenName = token.getName();

                CryptoStore store = token.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                for (int i = 0; i < list.length; i++) {
                    try {
                        @SuppressWarnings("unused")
                        PrivateKey key = CryptoManager.getInstance().findPrivKeyByCert(list[i]); // check for errors
                        Debug.trace("JssSubsystem getRootCerts: find private key "
                                + list[i].getNickname());
                    } catch (ObjectNotFoundException e) {
                        String nickname = list[i].getNickname();
                        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                            nickname = Constants.PR_INTERNAL_TOKEN_NAME + ":" + nickname;
                        }
                        X509CertImpl impl = null;

                        try {
                            Vector<X509Certificate> v;
                            if (vecTable.containsKey(nickname) == true) {
                                v = vecTable.get(nickname);
                            } else {
                                v = new Vector<X509Certificate>();
                            }
                            v.addElement(list[i]);
                            vecTable.put(nickname, v);
                            impl = new X509CertImpl(list[i].getEncoded());
                        } catch (CertificateException ex) {
                            // skip bad certificate
                            CMS.debug("bad certificate - " + nickname);
                            continue;
                        }
                        String serialno = impl.getSerialNumber().toString();
                        String issuer = impl.getIssuerDN().toString();
                        nvps.put(nickname + "," + serialno, issuer);
                        Debug.trace("getRootCerts: nickname=" + nickname + ", serialno=" +
                                serialno + ", issuer=" + issuer);
                        continue;
                    } catch (CryptoManager.NotInitializedException e) {
                        continue;
                    }
                }
                // convert hashtable of vectors to hashtable of arrays
                Enumeration<String> elms = vecTable.keys();

                while (elms.hasMoreElements()) {
                    String key = elms.nextElement();
                    Vector<X509Certificate> v = vecTable.get(key);
                    X509Certificate[] a = new X509Certificate[v.size()];

                    v.copyInto(a);
                    mNicknameMapCertsTable.put(key, a);
                }
            }
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        return nvps;

    }

    public NameValuePairs getUserCerts() throws EBaseException {
        NameValuePairs nvps = new NameValuePairs();
        try {
            @SuppressWarnings("unchecked")
            Enumeration<CryptoToken> enums = mCryptoManager.getAllTokens();

            while (enums.hasMoreElements()) {
                CryptoToken token = enums.nextElement();
                String tokenName = token.getName();

                CryptoStore store = token.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                for (int i = 0; i < list.length; i++) {
                    try {
                        @SuppressWarnings("unused")
                        PrivateKey key =
                                CryptoManager.getInstance().findPrivKeyByCert(list[i]); // check for errors
                        String nickname = list[i].getNickname();
                        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME) ||
                                tokenName.equals(Constants.PR_FULL_INTERNAL_TOKEN_NAME)) {
                            nickname = Constants.PR_INTERNAL_TOKEN_NAME + ":" + nickname;
                        }
                        X509CertImpl impl = null;

                        try {
                            impl = new X509CertImpl(list[i].getEncoded());
                        } catch (CertificateException e) {
                            // skip bad certificate
                            CMS.debug("bad certificate - " + nickname);
                            continue;
                        }
                        String serialno = impl.getSerialNumber().toString();
                        String issuer = impl.getIssuerDN().toString();
                        nvps.put(nickname + "," + serialno, issuer);
                        Debug.trace("getUserCerts: nickname=" + nickname + ", serialno=" +
                                serialno + ", issuer=" + issuer);
                    } catch (ObjectNotFoundException e) {
                        Debug.trace("JssSubsystem getUserCerts: cant find private key "
                                + list[i].getNickname());
                        continue;
                    } catch (CryptoManager.NotInitializedException e) {
                        continue;
                    }
                }
            }
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        return nvps;

    }

    /*
     * get all certificates on all tokens for Certificate Database Management
     */
    public NameValuePairs getAllCertsManage() throws EBaseException {

        /*
         * first get all CA certs (internal only),
         * then all user certs (both internal and external)
         */

        NameValuePairs pairs = getCACerts();

        if (mNicknameMapUserCertsTable != null) {
            mNicknameMapUserCertsTable.clear();
        } else {
            CMS.debug("JssSubsystem:: getAllCertsManage() : mNicknameMapCertsTable is null");
            throw new EBaseException("JssSubsystem:: getAllCertsManage() : mNicknameMapCertsTable is null");
        }

        try {
            @SuppressWarnings("unchecked")
            Enumeration<CryptoToken> enums = mCryptoManager.getAllTokens();

            while (enums.hasMoreElements()) {
                CryptoToken token = enums.nextElement();

                CryptoStore store = token.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                for (int i = 0; i < list.length; i++) {
                    String nickname = list[i].getNickname();
                    X509Certificate[] certificates =
                            CryptoManager.getInstance().findCertsByNickname(nickname);

                    mNicknameMapUserCertsTable.put(nickname, certificates);

                    X509CertImpl impl = null;

                    try {
                        impl = new X509CertImpl(list[i].getEncoded());
                    } catch (CertificateException e) {
                        // skip bad certificate
                        CMS.debug("bad certificate - " + nickname);
                        continue;
                    }
                    Date date = impl.getNotAfter();
                    String dateStr = mFormatter.format(date);
                    String vvalue = pairs.get(nickname);

                    /* always user cert here*/
                    String certValue = dateStr + "," + "u";

                    if (vvalue == null)
                        pairs.put(nickname, certValue);
                    else {
                        if (vvalue.endsWith(",u")) {
                            pairs.put(nickname, vvalue + ";" + certValue);
                        }
                    }

                }
            } /* while */
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
            // } catch (CertificateException e) {
            //    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()));
            //   throw new EBaseException(BaseResources.CERT_ERROR);
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        return pairs;
    }

    public NameValuePairs getCACerts() throws EBaseException {
        NameValuePairs pairs = new NameValuePairs();

        //InternalCertificate[] certs;
        X509Certificate[] certs;

        try {
            certs = CryptoManager.getInstance().getCACerts();
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_CA_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        }

        if (mNicknameMapCertsTable == null) {
            CMS.debug("JssSubsystem::getCACerts() - " + "mNicknameMapCertsTable is null!");
            throw new EBaseException("JssSubsystem::getCACerts() - mNicknameMapCertsTable is null");
        } else {
            mNicknameMapCertsTable.clear();
        }

        // a temp hashtable with vectors
        Hashtable<String, Vector<X509Certificate>> vecTable = new Hashtable<String, Vector<X509Certificate>>();

        for (int i = 0; i < certs.length; i++) {
            String nickname = certs[i].getNickname();

            /* build a table of our own */
            Vector<X509Certificate> v;

            if (vecTable.containsKey(nickname) == true) {
                v = vecTable.get(nickname);
            } else {
                v = new Vector<X509Certificate>();
            }
            v.addElement(certs[i]);
            vecTable.put(nickname, v);
        }

        // convert hashtable of vectors to hashtable of arrays
        Enumeration<String> elms = vecTable.keys();

        while (elms.hasMoreElements()) {
            String key = elms.nextElement();
            Vector<X509Certificate> v = vecTable.get(key);
            X509Certificate[] a = new X509Certificate[v.size()];

            v.copyInto(a);
            mNicknameMapCertsTable.put(key, a);
        }

        Enumeration<String> keys = mNicknameMapCertsTable.keys();

        while (keys.hasMoreElements()) {
            String nickname = keys.nextElement();
            X509Certificate[] value = mNicknameMapCertsTable.get(nickname);

            for (int i = 0; i < value.length; i++) {
                InternalCertificate icert = null;

                if (value[i] instanceof InternalCertificate)
                    icert = (InternalCertificate) value[i];
                else {
                    Debug.trace("cert is not an InternalCertificate");
                    Debug.trace("nickname: " + nickname + "  index " + i);
                    Debug.trace("cert: " + value[i]);
                    continue;
                }

                int flag = icert.getSSLTrust();
                String trust = "U";

                if ((InternalCertificate.TRUSTED_CLIENT_CA & flag) == InternalCertificate.TRUSTED_CLIENT_CA)
                    trust = "T";
                X509CertImpl impl = null;

                try {
                    impl = new X509CertImpl(icert.getEncoded());
                    Date date = impl.getNotAfter();
                    String dateStr = mFormatter.format(date);
                    String vvalue = pairs.get(nickname);
                    String certValue = dateStr + "," + trust;

                    if (vvalue == null)
                        pairs.put(nickname, certValue);
                    else {
                        pairs.put(nickname, vvalue + ";" + certValue);
                    }
                } catch (CertificateException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_SECURITY_GET_CA_CERT_FOR", nickname, e.toString()));
                    // allow it to continue with other certs even if one blows
                    // up
                    //            throw new EBaseException(BaseResources.CERT_ERROR);
                }
            }
        }
        return pairs;
    }

    public void trustCert(String nickname, String date, String trust) throws
            EBaseException {
        try {
            if (mNicknameMapCertsTable != null) {
                X509Certificate[] certs = mNicknameMapCertsTable.get(nickname);

                if (certs == null) {
                    EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TRUST_CERT", e.toString()));
                    throw e;
                } else {
                    for (int i = 0; i < certs.length; i++) {
                        X509Certificate cert = certs[i];
                        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
                        Date notAfter = certImpl.getNotAfter();
                        Date qualifier = mFormatter.parse(date);

                        if (notAfter.equals(qualifier)) {
                            if (cert instanceof InternalCertificate) {
                                if (trust.equals("Trust")) {
                                    int trustflag = InternalCertificate.TRUSTED_CA |
                                            InternalCertificate.TRUSTED_CLIENT_CA |
                                            InternalCertificate.VALID_CA;

                                    ((InternalCertificate) cert).setSSLTrust(trustflag);
                                } else
                                    ((InternalCertificate) cert).setSSLTrust(InternalCertificate.VALID_CA);
                                break;
                            } else {
                                throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
                            }
                        }
                    }
                }
            }
        } catch (ParseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TRUST_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_TRUST_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    /**
     * Delete the CA certificate from the perm database.
     *
     * @param nickname The nickname of the CA certificate.
     * @param notAfterTime The notAfter of the certificate. It is possible to get multiple
     *            certificates under the same nickname. If one of the certificates match the notAfterTime,
     *            then the certificate will get deleted. The format of the notAfterTime has to be
     *            in "MMMMM dd, yyyy HH:mm:ss" format.
     */
    public void deleteCACert(String nickname, String notAfterTime) throws EBaseException {
        try {
            if (mNicknameMapCertsTable != null) {
                X509Certificate[] certs = mNicknameMapCertsTable.get(nickname);

                if (certs == null) {
                    EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CA_CERT", e.toString()));
                    throw e;
                } else {
                    for (int i = 0; i < certs.length; i++) {
                        X509Certificate cert = certs[i];
                        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
                        Date notAfter = certImpl.getNotAfter();
                        Date qualifier = mFormatter.parse(notAfterTime);

                        if (notAfter.equals(qualifier)) {
                            if (cert instanceof TokenCertificate) {
                                TokenCertificate tcert = (TokenCertificate) cert;

                                tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                            } else {
                                CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                                CryptoStore store = token.getCryptoStore();

                                store.deleteCert(cert);
                            }
                            mNicknameMapCertsTable.remove(nickname);
                            break;
                        }
                    }
                }
            }
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (ParseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    /**
     * Delete any certificate from the any token.
     *
     * @param nickname The nickname of the certificate.
     * @param notAfterTime The notAfter of the certificate. It is possible to get multiple
     *            certificates under the same nickname. If one of the certificates match the notAfterTime,
     *            then the certificate will get deleted. The format of the notAfterTime has to be
     *            in "MMMMM dd, yyyy HH:mm:ss" format.
     */
    public void deleteCert(String nickname, String notAfterTime) throws EBaseException {
        boolean isUserCert = false;
        X509Certificate[] certs = null;

        try {
            if (mNicknameMapCertsTable != null) {
                certs = mNicknameMapCertsTable.get(nickname);
            }

            if (certs == null) {
                if (mNicknameMapUserCertsTable != null) {
                    certs = mNicknameMapUserCertsTable.get(nickname);
                    if (certs != null) {
                        CMS.debug("in mNicknameMapUserCertsTable, isUserCert is true");
                        isUserCert = true;
                    }

                } else
                    CMS.debug("mNicknameMapUserCertsTable is null");
            }

            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
                throw e;
            } else {

                for (int i = 0; i < certs.length; i++) {
                    X509Certificate cert = certs[i];
                    X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
                    Date notAfter = certImpl.getNotAfter();
                    Date qualifier = mFormatter.parse(notAfterTime);

                    if (notAfter.equals(qualifier)) {
                        if (cert instanceof TokenCertificate) {
                            TokenCertificate tcert = (TokenCertificate) cert;

                            tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                        } else {
                            CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                            CryptoStore store = token.getCryptoStore();

                            store.deleteCert(cert);
                        }
                        if (isUserCert == true) {
                            mNicknameMapUserCertsTable.remove(nickname);
                        } else {
                            mNicknameMapCertsTable.remove(nickname);
                        }
                        break;
                    }
                }
            }

        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (ParseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public void deleteTokenCertificate(String nickname, String pathname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            Principal principal = cert.getSubjectDN();
            DN dn = new DN(principal.getName());
            BigInteger serialno = cert.getSerialNumber();
            String suffix = "." + System.currentTimeMillis();
            String b64E = Utils.base64encode(cert.getEncoded());
            PrintStream stream = new PrintStream(new FileOutputStream(pathname + suffix));

            stream.println("-----BEGIN CERTIFICATE-----");
            stream.print(b64E);
            stream.println("-----END CERTIFICATE-----");
            stream.close();
            if (cert instanceof TokenCertificate) {
                TokenCertificate tcert = (TokenCertificate) cert;

                tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
            } else
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_NOT_TOKEN_CERT"));

            int index = nickname.indexOf(":");

            // the deleted certificate is on the hardware token. We should delete the same one from
            // the internal token.
            if (index > 0) {
                CryptoToken cToken = CryptoManager.getInstance().getInternalKeyStorageToken();
                CryptoStore store = cToken.getCryptoStore();
                X509Certificate[] allcerts = CryptoManager.getInstance().getCACerts();

                for (int i = 0; i < allcerts.length; i++) {
                    try {
                        X509CertImpl certImpl = new X509CertImpl(allcerts[i].getEncoded());
                        Principal certPrincipal = certImpl.getSubjectDN();
                        DN certdn = new DN(certPrincipal.getName());
                        BigInteger certSerialNo = certImpl.getSerialNumber();

                        if (dn.equals(certdn) && certSerialNo.compareTo(serialno) == 0) {
                            store.deleteCert(allcerts[i]);
                            break;
                        }
                    } catch (Exception ee) {
                        Debug.trace("JssSubsystem:deleteTokenCertificate: " + ee.toString());
                    }
                }
            }
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (ObjectNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public String getSubjectDN(String nickname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            X509CertImpl impl = new X509CertImpl(cert.getEncoded());

            return impl.getSubjectDN().getName();
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (ObjectNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public void setRootCertTrust(String nickname, String serialno,
            String issuerName, String trust) throws EBaseException {

        X509Certificate cert = getCertificate(nickname, serialno, issuerName);
        if (cert instanceof InternalCertificate) {
            if (trust.equals("trust")) {
                int trustflag = InternalCertificate.TRUSTED_CA |
                        InternalCertificate.TRUSTED_CLIENT_CA |
                        InternalCertificate.VALID_CA;

                ((InternalCertificate) cert).setSSLTrust(trustflag);
            } else {
                ((InternalCertificate) cert).setSSLTrust(InternalCertificate.VALID_CA);
            }
        }
    }

    public X509Certificate getCertificate(String nickname, String serialno,
            String issuerName) throws EBaseException {

        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            int i = 0;
            if (certs != null && certs.length > 0) {
                for (; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerDN().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        return certs[i];
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }

        return null;
    }

    public String getRootCertTrustBit(String nickname, String serialno,
            String issuerName) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            int i = 0;
            if (certs != null && certs.length > 0) {
                for (; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerDN().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        break;
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }

            String trust = "U";
            if (certs[i] instanceof InternalCertificate) {
                InternalCertificate icert = (InternalCertificate) certs[i];
                int flag = icert.getSSLTrust();
                if ((InternalCertificate.TRUSTED_CLIENT_CA & flag) == InternalCertificate.TRUSTED_CLIENT_CA)
                    trust = "T";
            } else
                trust = "N/A";
            return trust;
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public String getCertPrettyPrint(String nickname, String serialno,
            String issuerName, Locale locale) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerDN().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        break;
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
            CertPrettyPrint print = null;

            if (impl != null)
                print = new CertPrettyPrint(impl);

            if (print != null)
                return print.toString(locale);
            else
                return null;
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public String getCertPrettyPrintAndFingerPrint(String nickname, String serialno,
            String issuerName, Locale locale) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerDN().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        break;
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
            CertPrettyPrint print = null;
            String fingerPrint = "";

            if (impl != null) {
                print = new CertPrettyPrint(impl);
                fingerPrint = CMS.getFingerPrints(impl.getEncoded());
            }

            if ((print != null) && (fingerPrint != "")) {
                String pp = print.toString(locale) + "\n" +
                        "Certificate Fingerprints:" + '\n' + fingerPrint;
                return pp;
            } else
                return null;
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_SUCH_ALGORITHM", e.toString()));
        }
    }

    public String getCertPrettyPrint(String nickname, String date,
            Locale locale) throws EBaseException {
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            if ((certs == null || certs.length == 0) &&
                    mNicknameMapCertsTable != null) {
                certs = mNicknameMapCertsTable.get(nickname);
            }
            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
            X509CertImpl impl = null;
            Date qualifier = mFormatter.parse(date);

            for (int i = 0; i < certs.length; i++) {
                impl = new X509CertImpl(certs[i].getEncoded());
                Date d = impl.getNotAfter();

                if (d.equals(qualifier))
                    break;
            }

            CertPrettyPrint print = null;

            if (impl != null)
                print = new CertPrettyPrint(impl);

            if (print != null)
                return print.toString(locale);
            else
                return null;
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (ParseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public String getCertPrettyPrint(String b64E, Locale locale) throws EBaseException {
        try {
            try {
                byte[] b = KeyCertUtil.convertB64EToByteArray(b64E);
                X509CertImpl impl = new X509CertImpl(b);
                CertPrettyPrint print = new CertPrettyPrint(impl);

                return print.toString(locale);
            } catch (CertificateException e) {
                // failed to decode as a certificate, try decoding
                // as a PKCS #7 blob
                StringBuffer content = new StringBuffer();

                String noHeader = CertUtils.stripCertBrackets(b64E);
                String normalized = CertUtils.normalizeCertStr(noHeader);
                byte data[] = Utils.base64decode(normalized);

                ContentInfo ci = (ContentInfo)
                        ASN1Util.decode(ContentInfo.getTemplate(), data);

                if (!ci.getContentType().equals(ContentInfo.SIGNED_DATA)) {
                    throw new CertificateException(
                            "PKCS #7 structure is not a SignedData");
                }
                SignedData sd = (SignedData) ci.getInterpretedContent();

                if (!sd.hasCertificates()) {
                    throw new CertificateException(
                            "No certificates in PKCS #7 structure");
                }
                SET certs = sd.getCertificates();

                for (int i = 0; i < certs.size(); i++) {
                    Certificate cert = (Certificate) certs.elementAt(i);
                    X509CertImpl certImpl = new X509CertImpl(
                            ASN1Util.encode(cert));
                    CertPrettyPrint print = new CertPrettyPrint(certImpl);

                    content.append(print.toString(Locale.getDefault()));
                }

                return content.toString();
            }
        } catch (InvalidBERException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR",
                        "Failed to decode"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.getMessage()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    public X509CertImpl getSignedCert(KeyCertData data, String certType, java.security.PrivateKey priKey)
            throws EBaseException {
        CertificateInfo cert = null;

        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            cert = new CASigningCert(data);
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            cert = new OCSPSigningCert(data);
        } else if (certType.equals(Constants.PR_SERVER_CERT)) {
            cert = new SSLCert(data);
        } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            cert = new SSLSelfSignedCert(data);
        }

        if (cert == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        X509CertInfo certInfo = null;
        X509CertImpl signedCert = null;

        try {
            certInfo = cert.getCertInfo();
            SignatureAlgorithm sigAlg = (SignatureAlgorithm) data.get(Constants.PR_SIGNATURE_ALGORITHM);

            signedCert = KeyCertUtil.signCert(priKey, certInfo, sigAlg);
        } catch (NoSuchTokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SIGN_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SIGN_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (PQGParamGenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_SIGN_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
        }

        return signedCert;
    }

    public boolean isCACert(String fullNickname) throws EBaseException {
        try {
            X509Certificate cert = mCryptoManager.findCertByNickname(fullNickname);
            X509CertImpl impl = new X509CertImpl(cert.getEncoded());
            X509CertInfo certinfo = (X509CertInfo) impl.get(
                    X509CertImpl.NAME + "." + X509CertImpl.INFO);

            if (certinfo == null)
                return false;
            else {
                CertificateExtensions exts = (CertificateExtensions) certinfo.get(X509CertInfo.EXTENSIONS);

                if (exts == null)
                    return false;
                else {
                    try {
                        BasicConstraintsExtension ext = (BasicConstraintsExtension) exts
                                .get(BasicConstraintsExtension.NAME);

                        if (ext == null)
                            return false;
                        else {
                            Boolean bool = (Boolean) ext.get(BasicConstraintsExtension.IS_CA);

                            return bool.booleanValue();
                        }
                    } catch (IOException ee) {
                        return false;
                    }
                }
            }
        } catch (ObjectNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (CertificateEncodingException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        }
    }

    public CertificateExtensions getExtensions(String tokenname, String nickname)
            throws EBaseException {
        try {
            return KeyCertUtil.getExtensions(tokenname, nickname);
        } catch (NotInitializedException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (ObjectNotFoundException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    public void checkCertificateExt(String ext) throws EBaseException {
        KeyCertUtil.checkCertificateExt(ext);
    }

    public void checkKeyLength(String keyType, int keyLength, String certType, int minRSAKeyLen) throws EBaseException {
        //	KeyCertUtil.checkKeyLength(keyType, keyLength, certType, minRSAKeyLen);
    }

    public PQGParams getPQG(int keysize) {
        return KeyCertUtil.getPQG(keysize);
    }

    public PQGParams getCAPQG(int keysize, IConfigStore store)
            throws EBaseException {
        return KeyCertUtil.getCAPQG(keysize, store);
    }

    public CertificateExtensions getCertExtensions(String tokenname, String nickname)
            throws NotInitializedException, TokenException, ObjectNotFoundException,

            IOException, CertificateException {
        return KeyCertUtil.getExtensions(tokenname, nickname);
    }
}

class JSSDatabaseCloser extends org.mozilla.jss.DatabaseCloser {
    public JSSDatabaseCloser() throws Exception {
        super();
    }

    public void closeDatabases() {
        super.closeDatabases();
    }
}
