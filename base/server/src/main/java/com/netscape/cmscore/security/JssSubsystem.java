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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.NicknameConflictException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.UserCertConflictException;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.extensions.AuthInfoAccessExtension;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgIdDSA;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.URIName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11SecureRandom;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkcs7.SignedData;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.ssl.SSLCipher;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.security.ICryptoSubsystem;
import com.netscape.certsrv.security.KeyCertData;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.ldap.util.DN;

/**
 * Subsystem for initializing JSS
 * <P>
 *
 * @version $Revision$ $Date$
 */
public final class JssSubsystem implements ICryptoSubsystem {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JssSubsystem.class);

    public static final String ID = "jss";

    protected CMSEngine engine;
    protected JssSubsystemConfig config;
    private boolean mInited = false;
    private CryptoManager mCryptoManager = null;
    private SecureRandom random;
    private String obscureMethod = "zeroes";

    private Hashtable<String, X509Certificate[]> mNicknameMapCertsTable = new Hashtable<>();
    private Hashtable<String, X509Certificate[]> mNicknameMapUserCertsTable = new Hashtable<>();

    private FileInputStream devRandomInputStream = null;

    // This date format is to format the date string of the certificate in such a way as
    // May 01, 1999 01:55:55.
    private SimpleDateFormat mFormatter = new SimpleDateFormat("MMMMM dd, yyyy HH:mm:ss");

    // SSL related variables.

    private SSLConfig sslConfig;

    private static final String PROP_SSL_CIPHERPREF = Constants.PR_CIPHER_PREF;

    private static Hashtable<String, Integer> mCipherNames = new Hashtable<>();

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
    private static final SSLCipher[] ciphers = {
            SSLCipher.SSL2_RC4_128_WITH_MD5,
            SSLCipher.SSL2_RC4_128_EXPORT40_WITH_MD5,
            SSLCipher.SSL2_RC2_128_CBC_WITH_MD5,
            SSLCipher.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5,
            SSLCipher.SSL2_DES_64_CBC_WITH_MD5,
            SSLCipher.SSL2_DES_192_EDE3_CBC_WITH_MD5,
            SSLCipher.SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
            SSLCipher.SSL3_RSA_WITH_RC4_128_MD5,
            SSLCipher.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
            SSLCipher.SSL3_RSA_WITH_DES_CBC_SHA,
            SSLCipher.SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
            SSLCipher.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA,
            SSLCipher.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA,
            SSLCipher.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
            SSLCipher.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,
        };

    static {

        /* set ssl cipher string names. */
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

    /**
     * Constructs a Security service subsystem.
     */
    public JssSubsystem() {
    }

    public String getId() {
        return ID;
    }

    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));

    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    // Add entropy to the 'default' RNG token
    @Override
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

        logger.debug("JssSubsystem adding " + bits + " bits (" + bytes + " bytes) of entropy to default RNG token");
        logger.debug(Debug.dump(b));
        PK11SecureRandom sr = new PK11SecureRandom();
        sr.setSeed(b);
    }

    /**
     * Initializes the Jss security subsystem.
     * <P>
     */
    public void init(JssSubsystemConfig config) throws EBaseException {

        logger.debug("JssSubsystem: initializing JSS subsystem");

        if (mInited) {
            // This used to throw an exeception (e.g. - on Solaris).
            // If JSS is already initialized simply return.
            logger.debug("JssSubsystem: already initialized");
            return;
        }

        this.config = config;

        // If disabled, just return
        boolean enabled = config.isEnabled();
        logger.debug("JssSubsystem: enabled: " + enabled);

        if (!enabled) {
            return;
        }

        try {
            devRandomInputStream = new FileInputStream("/dev/urandom");
        } catch (IOException ioe) {
            // XXX - add new exception
        }

        String certDir = config.getNSSDatabaseDir();
        logger.debug("JssSubsystem: NSS database: " + certDir);

        InitializationValues vals = new InitializationValues(certDir, "", "", "secmod.db");
        vals.removeSunProvider = false;
        vals.installJSSProvider = true;

        try {
            logger.debug("JssSubsystem: initializing CryptoManager");
            CryptoManager.initialize(vals);
        } catch (AlreadyInitializedException e) {
            // do nothing
        } catch (Exception e) {
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            String message = CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.getMessage());
            logger.error("JssSubsystem: " + message, e);
            throw ex;
        }

        try {
            logger.debug("JssSubsystem: initializing SSL");
            mCryptoManager = CryptoManager.getInstance();
            initSSL();
        } catch (NotInitializedException e) {
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            String message = CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.getMessage());
            logger.error("JssSubsystem: " + message, e);
            throw ex;
        }

        // read jss.random.* properties
        // by default use PK11SecureRandom from JSS
        // see https://www.dogtagpki.org/wiki/Random_Number_Generator

        SecureRandomConfig secureRandomConfig = config.getSecureRandomConfig();

        try {
            // wrap random number generator with PKISecureRandom for audit
            SecureRandom random = SecureRandomFactory.create(secureRandomConfig);
            this.random = new PKISecureRandom(engine, random);

        } catch (GeneralSecurityException e) {
            throw new EBaseException(e);
        }

        obscureMethod = config.getObscureMethod();

        mInited = true;

        logger.debug("JssSubsystem: initialization complete");
    }

    public SecureRandom getRandomNumberGenerator() {
        return random;
    }

    public String generateSalt() {
        SecureRandom rnd = getRandomNumberGenerator();
        return Integer.toString(rnd.nextInt());
    }

    public void obscureBytes(byte[] memory) {
        obscureBytes(memory,null);
    }

    //Allow an optional explicit method, else read from config
    public void obscureBytes(byte[] memory, String method) {
        String methodName = "JssSubsystem.obscureBytes: ";
        if (memory == null || memory.length == 0) {
            //in case we want to log
            logger.debug(methodName + " memory null, ok, will return... ");
            return;
        }

        SecureRandom rnd = getRandomNumberGenerator();

        String actualMethod = obscureMethod;

        if(method != null)
            actualMethod = method;

        if ("zeroes".equals(actualMethod)) {
            logger.debug(methodName + " filling with zeroes, numBytes: " + memory.length);
            Arrays.fill(memory, (byte)0);
        } else {
            logger.debug(methodName + " filling with random data, numBytes: " + memory.length);

            if (rnd == null) {
                //fallback, should never happen
                rnd = new SecureRandom();
            }
            rnd.nextBytes(memory);
        }
    }

    public void obscureChars(char[] memory) {
        String methodName = "JssSubsystem.obscureBytes: ";
        if (memory == null || memory.length == 0)
            return;
        logger.debug(methodName + " filling with zeroes, numChars: " + memory.length);
        Arrays.fill(memory, (char) 0);
    }

    @Override
    public String getCipherVersion() throws EBaseException {
        return "cipherdomestic";
    }

    @Override
    public String getCipherPreferences() throws EBaseException {
        String cipherpref = "";

        if (sslConfig != null) {
            cipherpref = sslConfig.getCipherPreferences();
            if (cipherpref.equals("")) {
                cipherpref = DEFAULT_CIPHERPREF;
            }
        }
        return cipherpref;
    }

    public String getECType(String certType) throws EBaseException {
        // for SSL server, check the value of jss.ssl.sslserver.ectype
        return sslConfig == null ? "ECDHE" : sslConfig.getECType(certType);
    }

    @Override
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
            logger.warn("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_INSTALL_PROVIDER"));
        }
    }

    @Override
    public void setCipherPreferences(String cipherPrefs)
            throws EBaseException {
        if (sslConfig != null) {
            if (cipherPrefs.equals(""))
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_EMPTY_CIPHERPREFS"));
            sslConfig.setCipherPreferences(cipherPrefs);
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

        sslConfig = config.getSSLConfig();
        String sslCiphers = null;

        if (sslConfig != null)
            sslCiphers = getCipherPreferences();
        logger.trace("configured ssl cipher prefs is " + sslCiphers);

        // first, disable all ciphers, since JSS defaults to all-enabled
        for (int i = ciphers.length - 1; i >= 0; i--) {
            try {
                SSLSocket.setCipherPreferenceDefault(ciphers[i].getID(), false);
            } catch (SocketException e) {
            }
        }

        // the sslCiphers string will always contain something

        if (sslCiphers != null && sslCiphers.length() != 0) {
            StringTokenizer ciphers = new StringTokenizer(sslCiphers, ",");

            if (!ciphers.hasMoreTokens()) {
                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_INVALID_CIPHER", sslCiphers));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_PROPERTY", PROP_SSL_CIPHERPREF));
            }
            while (ciphers.hasMoreTokens()) {
                String cipher = ciphers.nextToken();
                Integer sslcipher = mCipherNames.get(cipher);

                if (sslcipher != null) {
                    String msg = "setting ssl cipher " + cipher;
                    logger.info("JssSubsystem: " + msg);

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
    public JssSubsystemConfig getConfigStore() {
        return config;
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
            boolean isClosing = config.getCloseNSSDatabase();
            if (isClosing) {
                JSSDatabaseCloser closer = new JSSDatabaseCloser();
                closer.closeDatabases();
            }
        } catch (Exception e) {
        }
    }

    @Override
    public String getInternalTokenName() throws EBaseException {
        CryptoToken c = mCryptoManager.getInternalKeyStorageToken();
        String name = "";

        try {
            name = c.getName();
        } catch (TokenException e) {
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()), e);
            throw ex;
        }

        return name;
    }

    @Override
    public String getTokenList() throws EBaseException {
        StringBuffer tokenList = new StringBuffer();

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
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()), e);
            throw ex;
        }

        if (tokenList.length()==0)
            return CryptoUtil.INTERNAL_TOKEN_NAME;
        return tokenList.append("," + CryptoUtil.INTERNAL_TOKEN_NAME).toString();
    }

    @Override
    public boolean isTokenLoggedIn(String name) throws EBaseException {
        try {
            CryptoToken ctoken = CryptoUtil.getKeyStorageToken(name);

            return ctoken.isLoggedIn();
        } catch (Exception e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"), e);
        }
    }

    @Override
    public void loggedInToken(String tokenName, String pwd) throws EBaseException {
        Password clk = new Password(pwd.toCharArray());
        try {
            CryptoToken ctoken = CryptoUtil.getKeyStorageToken(tokenName);
            ctoken.login(clk);
        } catch (Exception e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_TOKEN_LOGGED_IN", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"), e);
        } finally {
            clk.clear();
        }
    }

    @Override
    public String getCertSubjectName(String tokenname, String nickname)
            throws EBaseException {
        try {
            return KeyCertUtil.getCertSubjectName(tokenname, nickname);
        } catch (NoSuchTokenException | TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    @Override
    public String getAllCerts() throws EBaseException {
        StringBuffer certNames = new StringBuffer();

        try {
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
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()), e);
            throw ex;
        }

        return certNames.toString();
    }

    @Override
    public String getCertListWithoutTokenName(String name) throws EBaseException {

        CryptoToken c = null;
        StringBuffer certNames = new StringBuffer();

        try {
            c = CryptoUtil.getKeyStorageToken(name);

            if (c == null)
                return "";
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

        } catch (Exception e) {
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()), e);
            throw ex;
        }
    }

    public String getCertList(String name) throws EBaseException {

        CryptoToken c = null;
        StringBuffer certNames = new StringBuffer();

        try {
            c = CryptoUtil.getKeyStorageToken(name);

            if (c == null)
                return "";
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

        } catch (Exception e) {
            String[] params = { ID, e.toString() };
            EBaseException ex = new EBaseException(
                    CMS.getUserMessage("CMS_BASE_CREATE_SERVICE_FAILED", params));

            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GENERAL_ERROR", ex.toString()), e);
            throw ex;
        }
    }

    @Override
    public AlgorithmId getAlgorithmId(String algname, ConfigStore store)
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

    @Override
    public String getSignatureAlgorithm(String nickname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            X509CertImpl impl = new X509CertImpl(cert.getEncoded());

            return impl.getSigAlgName();
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (ObjectNotFoundException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_ALG", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    @Override
    public KeyPair getKeyPair(String nickname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            PrivateKey priKey = CryptoManager.getInstance().findPrivKeyByCert(cert);
            PublicKey publicKey = cert.getPublicKey();

            return new KeyPair(publicKey, priKey);
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: Key Pair Error " + e.getMessage(), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (ObjectNotFoundException e) {
            logger.error("JssSubsystem: Key Pair Error " + e.getMessage(), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: Key Pair Error " + e.getMessage(), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        }
    }

    @Override
    public KeyPair getKeyPair(CryptoToken token, String alg,
            int keySize) throws EBaseException {
        return getKeyPair(token, alg, keySize, null);
    }

    @Override
    public KeyPair getKeyPair(CryptoToken token, String alg,
            int keySize, PQGParams pqg) throws EBaseException {

        KeyPairAlgorithm kpAlg = null;

        if (alg.equals("RSA"))
            kpAlg = KeyPairAlgorithm.RSA;
        else {
            kpAlg = KeyPairAlgorithm.DSA;
        }

        try {
            return KeyCertUtil.generateKeyPair(token, kpAlg, keySize, pqg);
        } catch (InvalidParameterException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEYSIZE_PARAMS",
                        "" + keySize));
        } catch (PQGParamGenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
        } catch (NoSuchAlgorithmException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED",
                        kpAlg.toString()));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_KEY_GEN_FAILED"));
        } catch (InvalidAlgorithmParameterException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_KEY_PAIR", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", "DSA"));
        }
    }

    @Override
    public void isX500DN(String dn) throws EBaseException {
        try {
            new X500Name(dn); // check for errors
        } catch (IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_X500_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_X500_NAME", dn));
        }
    }

    @Override
    public String getCertRequest(String subjectName, KeyPair kp)
            throws EBaseException {
        try {
            org.mozilla.jss.netscape.security.pkcs.PKCS10 pkcs = KeyCertUtil.getCertRequest(subjectName, kp);
            return CertUtil.toPEM(pkcs);
        } catch (NoSuchAlgorithmException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", ""));
        } catch (NoSuchProviderException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PROVIDER_NOT_SUPPORTED"));
        } catch (InvalidKeyException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY"));
        } catch (IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_REQ_FAILED"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_CERT", e.toString()));
        } catch (SignatureException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_REQUEST", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_SIGNATURE"));
        } catch (Exception e) {
            throw new EBaseException(e);
        }
    }

    @Override
    public void importCert(String b64E, String nickname, String certType)
            throws EBaseException {
        try {
            KeyCertUtil.importCert(b64E, nickname, certType);
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            String eString = e.toString();
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            if (eString.contains("Failed to find certificate that was just imported")) {
                throw new EBaseException(eString);
            }
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (UserCertConflictException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_USERCERT_CONFLICT"));
        } catch (NicknameConflictException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NICKNAME_CONFLICT"));
        } catch (NoSuchItemOnTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        }
    }

    @Override
    public KeyPair getKeyPair(KeyCertData properties) throws EBaseException {
        String tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        String keyType = "RSA";
        int keyLength = 512;

        String tmp = (String) properties.get(Constants.PR_TOKEN_NAME);

        if (!CryptoUtil.isInternalToken(tmp))
            tokenName = tmp;
        tmp = (String) properties.get(Constants.PR_KEY_TYPE);
        if (tmp != null)
            keyType = tmp;
        tmp = (String) properties.get(Constants.PR_KEY_LENGTH);
        if (tmp != null)
            keyLength = Integer.parseInt(tmp);

        CryptoToken token;
        try {
            token = CryptoUtil.getKeyStorageToken(tokenName);
        } catch (NotInitializedException | NoSuchTokenException e) {
            throw new EBaseException("Unable to find token: " + tokenName, e);
        }
        return getKeyPair(token, keyType, keyLength);
    }

    @Override
    public KeyPair getECCKeyPair(KeyCertData properties) throws EBaseException {
        String tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        String keyCurve = "nistp521";

        String tmp = (String) properties.get(Constants.PR_TOKEN_NAME);
        if (tmp != null)
            tokenName = tmp;

        tmp = (String) properties.get(Constants.PR_KEY_CURVENAME);
        if (tmp != null)
            keyCurve = tmp;

        String certType = (String) properties.get(Constants.RS_ID);

        CryptoToken token;
        try {
            token = CryptoUtil.getKeyStorageToken(tokenName);
        } catch (NotInitializedException | NoSuchTokenException e) {
            throw new EBaseException("Unable to find token: " + tokenName, e);
        }
        return getECCKeyPair(token, keyCurve, certType);
    }

    @Override
    public KeyPair getECCKeyPair(CryptoToken token, String keyCurve, String certType) throws EBaseException {
        KeyPair pair = null;

        if ((keyCurve == null) || (keyCurve.equals("")))
            keyCurve = "nistp521";

        String ectype = getECType(certType);

        try {
            Usage[] usages = null;
            Usage[] usagesMask = ectype.equals("ECDHE") ? CryptoUtil.ECDHE_USAGES_MASK : CryptoUtil.ECDH_USAGES_MASK;

            pair = CryptoUtil.generateECCKeyPair(
                    token,
                    keyCurve,
                    usages,
                    usagesMask);

        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));

        } catch (NoSuchTokenException | TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));

        } catch (NoSuchAlgorithmException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ECC_KEY", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_SUCH_ALGORITHM", e.toString()));

        } catch (Exception e) {
            throw new EBaseException(e);
        }

        return pair;
    }

    @Override
    public void importCert(X509CertImpl signedCert, String nickname,
            String certType) throws EBaseException {

        try {
            KeyCertUtil.importCert(signedCert, nickname, certType);
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ENCODE_CERT_FAILED"));
        } catch (UserCertConflictException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_USERCERT_CONFLICT"));
        } catch (NicknameConflictException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NICKNAME_CONFLICT"));
        } catch (NoSuchItemOnTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IMPORT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        }
    }

    public NameValuePairs getCertInfo(String b64E) throws EBaseException {
        try {
            byte[] b = KeyCertUtil.convertB64EToByteArray(b64E);
            X509CertImpl impl = new X509CertImpl(b);
            NameValuePairs results = new NameValuePairs();

            results.put(Constants.PR_CERT_SUBJECT_NAME, impl.getSubjectName().getName());
            results.put(Constants.PR_ISSUER_NAME, impl.getIssuerName().getName());
            results.put(Constants.PR_SERIAL_NUMBER, impl.getSerialNumber().toString());
            results.put(Constants.PR_BEFORE_VALIDDATE, impl.getNotBefore().toString());
            results.put(Constants.PR_AFTER_VALIDDATE, impl.getNotAfter().toString());

            // fingerprint is using MD5 hash

            return results;
        } catch (CertificateException | IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_CERT_INFO", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        }
    }

    @Override
    public void deleteUserCert(String nickname, String serialno, String issuername)
            throws EBaseException {
        try {
            X509Certificate cert = getCertificate(nickname, serialno, issuername);
            if (cert instanceof PK11Cert tcert) {
                logger.debug("*** deleting this token cert");
                tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                logger.debug("*** finish deleting this token cert");
            } else {
                CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                CryptoStore store = token.getCryptoStore();

                logger.debug("*** deleting this interna cert");
                store.deleteCert(cert);
                logger.debug("*** removing this interna cert");
            }
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        }
    }

    @Override
    public void deleteRootCert(String nickname, String serialno,
            String issuername) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (CryptoUtil.isInternalToken(tokenname)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = mNicknameMapCertsTable.get(nickname);

            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CA_CERT", e.toString()));
                throw e;
            }
            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = certs[i];
                X509CertImpl impl = new X509CertImpl(cert.getEncoded());
                String num = impl.getSerialNumber().toString();
                String issuer = impl.getIssuerName().toString();
                logger.debug("*** num " + num);
                logger.debug("*** issuer " + issuer);
                if (num.equals(serialno) && issuername.equals(issuer)) {
                    logger.debug("*** removing root cert");
                    if (cert instanceof PK11Cert tcert) {
                        logger.debug("*** deleting this token cert");
                        tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                        logger.debug("*** finish deleting this token cert");
                    } else {
                        CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                        CryptoStore store = token.getCryptoStore();

                        logger.debug("*** deleting this interna cert");
                        store.deleteCert(cert);
                        logger.debug("*** removing this interna cert");
                    }
                    mNicknameMapCertsTable.remove(nickname);
                    break;
                }
            }

        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
    public NameValuePairs getRootCerts() throws EBaseException {
        NameValuePairs nvps = new NameValuePairs();
        try {
            Enumeration<CryptoToken> enums = mCryptoManager.getAllTokens();
            mNicknameMapCertsTable.clear();

            // a temp hashtable with vectors
            Hashtable<String, Vector<X509Certificate>> vecTable = new Hashtable<>();

            while (enums.hasMoreElements()) {
                CryptoToken token = enums.nextElement();
                String tokenName = token.getName();

                CryptoStore store = token.getCryptoStore();
                X509Certificate[] list = store.getCertificates();

                for (int i = 0; i < list.length; i++) {
                    try {
                        @SuppressWarnings("unused")
                        PrivateKey key = CryptoManager.getInstance().findPrivKeyByCert(list[i]); // check for errors
                        logger.trace("JssSubsystem getRootCerts: find private key "
                                + list[i].getNickname());
                    } catch (ObjectNotFoundException e) {
                        String nickname = list[i].getNickname();
                        if (CryptoUtil.isInternalToken(tokenName)) {
                            nickname = CryptoUtil.INTERNAL_TOKEN_NAME + ":" + nickname;
                        }
                        X509CertImpl impl = null;

                        try {
                            Vector<X509Certificate> v;
                            if (vecTable.containsKey(nickname)) {
                                v = vecTable.get(nickname);
                            } else {
                                v = new Vector<>();
                            }
                            v.addElement(list[i]);
                            vecTable.put(nickname, v);
                            impl = new X509CertImpl(list[i].getEncoded());
                        } catch (CertificateException ex) {
                            // skip bad certificate
                            logger.warn("bad certificate - " + nickname);
                            continue;
                        }
                        String serialno = impl.getSerialNumber().toString();
                        String issuer = impl.getIssuerName().toString();
                        nvps.put(nickname + "," + serialno, issuer);
                        logger.trace("getRootCerts: nickname=" + nickname + ", serialno=" +
                                serialno + ", issuer=" + issuer);
                    } catch (NotInitializedException e) {
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
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        return nvps;

    }

    @Override
    public NameValuePairs getUserCerts() throws EBaseException {
        NameValuePairs nvps = new NameValuePairs();
        try {
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
                        if (CryptoUtil.isInternalToken(tokenName)) {
                            nickname = CryptoUtil.INTERNAL_TOKEN_NAME + ":" + nickname;
                        }
                        X509CertImpl impl = null;

                        try {
                            impl = new X509CertImpl(list[i].getEncoded());
                        } catch (CertificateException e) {
                            // skip bad certificate
                            logger.warn("bad certificate - " + nickname);
                            continue;
                        }
                        String serialno = impl.getSerialNumber().toString();
                        String issuer = impl.getIssuerName().toString();
                        nvps.put(nickname + "," + serialno, issuer);
                        logger.trace("getUserCerts: nickname=" + nickname + ", serialno=" +
                                serialno + ", issuer=" + issuer);
                    } catch (ObjectNotFoundException e) {
                        logger.trace("JssSubsystem getUserCerts: cant find private key "
                                + list[i].getNickname());
                    } catch (NotInitializedException e) {
                    }
                }
            }
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        return nvps;

    }

    /*
     * get all certificates on all tokens for Certificate Database Management
     */
    @Override
    public NameValuePairs getAllCertsManage() throws EBaseException {

        /*
         * first get all CA certs (internal only),
         * then all user certs (both internal and external)
         */

        NameValuePairs pairs = getCACerts();
        mNicknameMapUserCertsTable.clear();

        try {
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
                        logger.warn("bad certificate - " + nickname);
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
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_ALL_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }

        return pairs;
    }

    @Override
    public NameValuePairs getCACerts() throws EBaseException {
        NameValuePairs pairs = new NameValuePairs();

        X509Certificate[] certs;

        try {
            certs = CryptoManager.getInstance().getCACerts();
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_CA_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        }

        mNicknameMapCertsTable.clear();

        // a temp hashtable with vectors
        Hashtable<String, Vector<X509Certificate>> vecTable = new Hashtable<>();

        for (int i = 0; i < certs.length; i++) {
            String nickname = certs[i].getNickname();

            /* build a table of our own */
            Vector<X509Certificate> v;

            if (vecTable.containsKey(nickname)) {
                v = vecTable.get(nickname);
            } else {
                v = new Vector<>();
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
                if (!(value[i] instanceof PK11Cert icert)) {
                    logger.trace("cert is not an InternalCertificate");
                    logger.trace("nickname: " + nickname + "  index " + i);
                    logger.trace("cert: " + value[i]);
                    continue;
                }

                int flag = icert.getSSLTrust();
                String trust = "U";

                if ((PK11Cert.TRUSTED_CLIENT_CA & flag) == PK11Cert.TRUSTED_CLIENT_CA)
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
                    logger.warn("JssSubsystem: " +
                            CMS.getLogMessage("CMSCORE_SECURITY_GET_CA_CERT_FOR", nickname, e.toString()), e);
                    // allow it to continue with other certs even if one blows up
                }
            }
        }
        return pairs;
    }

    @Override
    public void trustCert(String nickname, String date, String trust) throws
            EBaseException {
        try {
            X509Certificate[] certs = mNicknameMapCertsTable.get(nickname);

            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_TRUST_CERT", e.toString()));
                throw e;
            }
            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = certs[i];
                X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
                Date notAfter = certImpl.getNotAfter();
                Date qualifier = mFormatter.parse(date);

                if (notAfter.equals(qualifier)) {
                    if (cert instanceof PK11Cert internalCertificate) {
                        if (trust.equals("Trust")) {
                            int trustflag = PK11Cert.TRUSTED_CA |
                                    PK11Cert.TRUSTED_CLIENT_CA |
                                    PK11Cert.VALID_CA;

                            internalCertificate.setSSLTrust(trustflag);
                        } else
                            internalCertificate.setSSLTrust(PK11Cert.VALID_CA);
                        break;
                    }
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
                }
            }

        } catch (ParseException | CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_TRUST_CERT", e.toString()), e);
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
            X509Certificate[] certs = mNicknameMapCertsTable.get(nickname);

            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CA_CERT", e.toString()));
                throw e;
            }
            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = certs[i];
                X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
                Date notAfter = certImpl.getNotAfter();
                Date qualifier = mFormatter.parse(notAfterTime);

                if (notAfter.equals(qualifier)) {
                    if (cert instanceof PK11Cert tcert) {
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

        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (ParseException | CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
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
    @Override
    public void deleteCert(String nickname, String notAfterTime) throws EBaseException {
        boolean isUserCert = false;
        X509Certificate[] certs = null;

        try {
            certs = mNicknameMapCertsTable.get(nickname);

            if (certs == null) {
                certs = mNicknameMapUserCertsTable.get(nickname);
                if (certs != null) {
                    logger.debug("in mNicknameMapUserCertsTable, isUserCert is true");
                    isUserCert = true;
                }
            }

            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()));
                throw e;
            }
            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = certs[i];
                X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
                Date notAfter = certImpl.getNotAfter();
                Date qualifier = mFormatter.parse(notAfterTime);

                if (notAfter.equals(qualifier)) {
                    if (cert instanceof PK11Cert tcert) {
                        tcert.getOwningToken().getCryptoStore().deleteCert(tcert);
                    } else {
                        CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();
                        CryptoStore store = token.getCryptoStore();

                        store.deleteCert(cert);
                    }
                    if (isUserCert) {
                        mNicknameMapUserCertsTable.remove(nickname);
                    } else {
                        mNicknameMapCertsTable.remove(nickname);
                    }
                    break;
                }
            }

        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (ParseException | CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
    public void deleteTokenCertificate(String nickname, String pathname) throws EBaseException {
        String suffix = "." + System.currentTimeMillis();

        try (PrintStream stream = new PrintStream(new FileOutputStream(pathname + suffix))) {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            Principal principal = cert.getSubjectDN();
            DN dn = new DN(principal.getName());
            BigInteger serialno = cert.getSerialNumber();
            String b64E = Utils.base64encode(cert.getEncoded(), true);

            stream.println(Cert.HEADER);
            stream.print(b64E);
            stream.println(Cert.FOOTER);
            if (cert instanceof PK11Cert tcert) {
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
                        Principal certPrincipal = certImpl.getSubjectName();
                        DN certdn = new DN(certPrincipal.getName());
                        BigInteger certSerialNo = certImpl.getSerialNumber();

                        if (dn.equals(certdn) && certSerialNo.compareTo(serialno) == 0) {
                            store.deleteCert(allcerts[i]);
                            break;
                        }
                    } catch (Exception ee) {
                        logger.error("JssSubsystem: deleteTokenCertificate: " + ee.getMessage(), ee);
                    }
                }
            }
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (NoSuchItemOnTokenException | ObjectNotFoundException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ITEM_NOT_FOUND_ON_TOKEN"));
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (CertificateEncodingException | IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_DELETE_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
    public String getSubjectDN(String nickname) throws EBaseException {
        try {
            X509Certificate cert = CryptoManager.getInstance().findCertByNickname(nickname);
            X509CertImpl impl = new X509CertImpl(cert.getEncoded());

            return impl.getSubjectName().getName();
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (ObjectNotFoundException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_SUBJECT_NAME", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
    public void setRootCertTrust(String nickname, String serialno,
            String issuerName, String trust) throws EBaseException {

        X509Certificate cert = getCertificate(nickname, serialno, issuerName);
        if (cert instanceof PK11Cert internalCertificate) {
            if (trust.equals("trust")) {
                int trustflag = PK11Cert.TRUSTED_CA |
                        PK11Cert.TRUSTED_CLIENT_CA |
                        PK11Cert.VALID_CA;

                internalCertificate.setSSLTrust(trustflag);
            } else {
                internalCertificate.setSSLTrust(PK11Cert.VALID_CA);
            }
        }
    }

    public X509Certificate getCertificate(String nickname, String serialno,
            String issuerName) throws EBaseException {

        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (CryptoUtil.isInternalToken(tokenname)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            int i = 0;
            if (certs != null && certs.length > 0) {
                for (; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerName().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        return certs[i];
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }

        return null;
    }

    @Override
    public String getRootCertTrustBit(String nickname, String serialno,
            String issuerName) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (CryptoUtil.isInternalToken(tokenname)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            int i = 0;
            if (certs != null && certs.length > 0) {
                for (; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerName().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        break;
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }

            String trust = "U";
            if (certs[i] instanceof PK11Cert icert) {
                int flag = icert.getSSLTrust();
                if ((PK11Cert.TRUSTED_CLIENT_CA & flag) == PK11Cert.TRUSTED_CLIENT_CA)
                    trust = "T";
            } else
                trust = "N/A";
            return trust;
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
    public String getCertPrettyPrint(String nickname, String serialno,
            String issuerName, Locale locale) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (CryptoUtil.isInternalToken(tokenname)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerName().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        break;
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
            CertPrettyPrint print = null;

            if (impl != null)
                print = new CertPrettyPrint(impl);

            return print == null ? null : print.toString(locale);
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
    public String getCertPrettyPrintAndFingerPrint(String nickname, String serialno,
            String issuerName, Locale locale) throws EBaseException {
        int index = nickname.indexOf(":");
        String tokenname = nickname.substring(0, index);
        if (CryptoUtil.isInternalToken(tokenname)) {
            nickname = nickname.substring(index + 1);
        }
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            X509CertImpl impl = null;
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    impl = new X509CertImpl(certs[i].getEncoded());
                    if (impl.getIssuerName().toString().equals(issuerName) &&
                            impl.getSerialNumber().toString().equals(serialno))
                        break;
                }
            } else {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
                throw e;
            }
            CertPrettyPrint print = null;
            String fingerPrint = "";

            if (impl != null) {
                print = new CertPrettyPrint(impl);
                fingerPrint = CertUtils.getFingerPrints(impl.getEncoded());
            }

            if (print == null || fingerPrint.isEmpty()) {
                return null;
            }
            return print.toString(locale) + "\n" + "Certificate Fingerprints:" + '\n' + fingerPrint;
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        } catch (NoSuchAlgorithmException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_NO_SUCH_ALGORITHM", e.toString()));
        }
    }

    @Override
    public String getCertPrettyPrint(String nickname, String date,
            Locale locale) throws EBaseException {
        try {
            X509Certificate[] certs = CryptoManager.getInstance().findCertsByNickname(nickname);

            if (certs == null || certs.length == 0) {
                certs = mNicknameMapCertsTable.get(nickname);
            }
            if (certs == null) {
                EBaseException e = new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));

                logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()));
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
            return print == null ? null : print.toString(locale);
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));
        } catch (CertificateException | ParseException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    @Override
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
                byte[] data = Utils.base64decode(normalized);

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
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR",
                        "Failed to decode"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.getMessage()));
        } catch (IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_PRINT_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    public X509CertImpl signCert(
            java.security.PrivateKey privateKey,
            X509CertInfo certInfo,
            SignatureAlgorithm sigAlg)
            throws NoSuchTokenException, EBaseException, NotInitializedException {

        try (DerOutputStream out = new DerOutputStream()) {

            CertificateAlgorithmId sId = (CertificateAlgorithmId) certInfo.get(X509CertInfo.ALGORITHM_ID);
            AlgorithmId sigAlgId = (AlgorithmId) sId.get(CertificateAlgorithmId.ALGORITHM);

            org.mozilla.jss.crypto.PrivateKey priKey = (org.mozilla.jss.crypto.PrivateKey) privateKey;
            CryptoToken token = priKey.getOwningToken();

            DerOutputStream tmp = new DerOutputStream();
            certInfo.encode(tmp);

            Signature signer = token.getSignatureContext(sigAlg);

            signer.initSign(priKey);
            signer.update(tmp.toByteArray());
            byte[] signed = signer.sign();

            sigAlgId.encode(tmp);
            tmp.putBitString(signed);

            out.write(DerValue.tag_Sequence, tmp);

            X509CertImpl signedCert = new X509CertImpl(out.toByteArray());

            return signedCert;

        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_SIGNED_FAILED", e.toString()));

        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", e.toString()));

        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR_1", e.toString()));

        } catch (SignatureException e) {
            logger.error("JssSubsystem: "+ e.getMessage(), e);
            engine.checkForAndAutoShutdown();
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_SIGNED_FAILED", e.toString()));

        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1", e.toString()));

        } catch (CertificateException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    }

    public void setAuthInfoAccess(
            CertificateExtensions ext,
            KeyCertData properties
            ) throws Exception {

        String aia = properties.getAIA();
        if (aia == null || !aia.equals(Constants.TRUE)) {
            return;
        }

        EngineConfig config = engine.getConfig();
        String hostname = config.getHostname();
        String port = engine.getEENonSSLPort();

        AuthInfoAccessExtension aiaExt = new AuthInfoAccessExtension(false);
        if (hostname != null && port != null) {
            String location = "http://" + hostname + ":" + port + "/ca/ocsp";
            GeneralName ocspName = new GeneralName(new URIName(location));
            aiaExt.addAccessDescription(AuthInfoAccessExtension.METHOD_OCSP, ocspName);
        }

        ext.set(AuthInfoAccessExtension.NAME, aiaExt);
    }

    @Override
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

            CertificateExtensions exts = (CertificateExtensions) certInfo.get(X509CertInfo.EXTENSIONS);
            KeyCertData keyCertData = cert.getProperties();
            setAuthInfoAccess(exts, keyCertData);

            SignatureAlgorithm sigAlg = (SignatureAlgorithm) data.get(Constants.PR_SIGNATURE_ALGORITHM);

            signedCert = signCert(priKey, certInfo, sigAlg);

        } catch (NoSuchTokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_SIGN_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", ""));

        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_SIGN_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));

        } catch (PQGParamGenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_SIGN_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));

        } catch (Exception e) {
            logger.error("JssSubsystem: Unable to sign certificate: " + e.getMessage(), e);
            throw new EBaseException("Unable to sign certificate: " + e.getMessage(), e);
        }

        return signedCert;
    }

    @Override
    public boolean isCACert(String fullNickname) throws EBaseException {
        try {
            X509Certificate cert = mCryptoManager.findCertByNickname(fullNickname);
            X509CertImpl impl = new X509CertImpl(cert.getEncoded());
            X509CertInfo certinfo = (X509CertInfo) impl.get(
                    X509CertImpl.NAME + "." + X509CertImpl.INFO);

            if (certinfo == null)
                return false;
            CertificateExtensions exts = (CertificateExtensions) certinfo.get(X509CertInfo.EXTENSIONS);

            if (exts == null)
                return false;
            try {
                BasicConstraintsExtension ext = (BasicConstraintsExtension) exts
                        .get(BasicConstraintsExtension.NAME);

                if (ext == null)
                    return false;
                Boolean bool = (Boolean) ext.get(BasicConstraintsExtension.IS_CA);

                return bool.booleanValue();
            } catch (IOException ee) {
                return false;
            }
        } catch (ObjectNotFoundException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (TokenException | CertificateEncodingException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        } catch (IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_IS_CA_CERT", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        }
    }

    @Override
    public CertificateExtensions getExtensions(String tokenname, String nickname)
            throws EBaseException {
        try {
            return KeyCertUtil.getExtensions(tokenname, nickname);
        } catch (NotInitializedException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        } catch (TokenException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR"));
        } catch (ObjectNotFoundException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_NOT_FOUND"));
        } catch (IOException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_DECODE_CERT_FAILED"));
        } catch (CertificateException e) {
            logger.error("JssSubsystem: " + CMS.getLogMessage("CMSCORE_SECURITY_GET_EXTENSIONS", e.toString()), e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ""));
        }
    }

    @Override
    public void checkCertificateExt(String ext) throws EBaseException {
        KeyCertUtil.checkCertificateExt(ext);
    }

    public void checkKeyLength(String keyType, int keyLength, String certType, int minRSAKeyLen) throws EBaseException {
    }

    @Override
    public PQGParams getPQG(int keysize) {
        return KeyCertUtil.getPQG(keysize);
    }

    @Override
    public PQGParams getCAPQG(int keysize, ConfigStore store)
            throws EBaseException {
        return KeyCertUtil.getCAPQG(keysize, store);
    }

    @Override
    public CertificateExtensions getCertExtensions(String tokenname, String nickname)
            throws NotInitializedException, TokenException, ObjectNotFoundException,

            IOException, CertificateException {
        return KeyCertUtil.getExtensions(tokenname, nickname);
    }

    public static void main(String[] args) throws Exception {

        JssSubsystem jss = new JssSubsystem();

        byte[] test = {1,1,1,1,1};

        for(int i = 0 ; i < 5 ; i++) {
            System.out.println("test[" + i + "] : value before: " + test[i]);
        }

        jss.obscureBytes(test,"random");

        System.out.println("******************");
        for(int i = 0 ; i < 5 ; i++) {
            System.out.println("test[" + i + "] : value now: " + test[i]);
        }


    }
}

class JSSDatabaseCloser extends org.mozilla.jss.DatabaseCloser {
    public JSSDatabaseCloser() throws Exception {
        super();
    }

    @Override
    public void closeDatabases() {
        super.closeDatabases();
    }
}
