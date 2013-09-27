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
package com.netscape.kra;

import java.io.CharConversionException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PBEKeyGenParams;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.kra.EKRAException;
import com.netscape.certsrv.kra.IJoinShares;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.kra.IShare;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.security.Credential;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cmsutil.util.Utils;

/**
 * A class represents a storage key unit. Currently, this
 * is implemented with cryptix, the final implementation
 * should be built on JSS/HCL.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class StorageKeyUnit extends EncryptionUnit implements
        ISubsystem, IStorageKeyUnit {

    private IConfigStore mConfig = null;

    // private RSAPublicKey mPublicKey = null;
    // private RSAPrivateKey mPrivateKey = null;

    private IConfigStore mStorageConfig = null;
    private IKeyRecoveryAuthority mKRA = null;
    private String mTokenFile = null;
    private X509Certificate mCert = null;
    private CryptoManager mManager = null;
    private CryptoToken mToken = null;
    private PrivateKey mPrivateKey = null;
    private byte mPrivateKeyData[] = null;
    private boolean mKeySplitting = false;

    private static final String PROP_N = "n";
    private static final String PROP_M = "m";
    private static final String PROP_UID = "uid";
    private static final String PROP_SHARE = "share";
    private static final String PROP_HARDWARE = "hardware";
    private static final String PROP_LOGOUT = "logout";
    public static final String PROP_NICKNAME = "nickName";
    public static final String PROP_KEYDB = "keydb";
    public static final String PROP_CERTDB = "certdb";
    public static final String PROP_MN = "mn";

    /**
     * Constructs this token.
     */
    public StorageKeyUnit() {
        super();
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return "storageKeyUnit";
    }

    /**
     * Sets subsystem identifier. Once the system is
     * loaded, system identifier cannot be changed
     * dynamically.
     */
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_INVALID_OPERATION"));
    }

    /**
     * return true if byte arrays are equal, false otherwise
     */
    private boolean byteArraysMatch(byte a[], byte b[]) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Initializes this subsystem.
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mKRA = (IKeyRecoveryAuthority) owner;
        mConfig = config;

        mKeySplitting = owner.getConfigStore().getBoolean("keySplitting", false);

        try {
            mManager = CryptoManager.getInstance();
            mToken = getToken();
        } catch (org.mozilla.jss.CryptoManager.NotInitializedException e) {
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_STORAGE_INIT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }

        if (mConfig.getString(PROP_HARDWARE, null) != null) {
            System.setProperty("cms.skip_token", mConfig.getString(PROP_HARDWARE));

            // The strategy here is to read all the certs in the token
            // and cycle through them until we find one that matches the
            // kra-cert.db file

            if (mKeySplitting) {

                byte certFileData[] = null;
                FileInputStream fi = null;
                try {
                    File certFile = new File(
                            mConfig.getString(PROP_CERTDB));

                    certFileData = new byte[
                            (Long.valueOf(certFile.length())).intValue()];
                    fi = new FileInputStream(certFile);

                    fi.read(certFileData);
                    // pick up cert by nickName

                } catch (IOException e) {
                    mKRA.log(ILogger.LL_INFO,
                            CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_CERT", e.toString()));
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
                } finally {
                    try {
                        if (fi != null)
                            fi.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                try {
                    X509Certificate certs[] =
                            getToken().getCryptoStore().getCertificates();
                    for (int i = 0; i < certs.length; i++) {
                        if (byteArraysMatch(certs[i].getEncoded(), certFileData)) {
                            mCert = certs[i];
                        }
                    }
                    if (mCert == null) {
                        mKRA.log(ILogger.LL_FAILURE,
                                "Storage Cert could not be initialized. No cert in token matched kra-cert file");
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", "mCert == null"));
                    } else {
                        mKRA.log(ILogger.LL_INFO, "Using Storage Cert " + mCert.getSubjectDN());
                    }
                } catch (CertificateEncodingException e) {
                    mKRA.log(ILogger.LL_FAILURE, "Error encoding cert ");
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
                } catch (TokenException e) {
                    mKRA.log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_CERT", e.toString()));
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
                }
            }

        } else {

            // read certificate from file
            byte certData[] = null;
            FileInputStream fi = null;
            try {
                if (mKeySplitting) {
                    File certFile = new File(
                            mConfig.getString(PROP_CERTDB));

                    certData = new byte[
                            (Long.valueOf(certFile.length())).intValue()];
                    fi = new FileInputStream(certFile);

                    fi.read(certData);
                    // pick up cert by nickName
                    mCert = mManager.findCertByNickname(
                            config.getString(PROP_NICKNAME));

                } else {
                    mCert = mManager.findCertByNickname(
                            config.getString(PROP_NICKNAME));
                }
            } catch (IOException e) {
                mKRA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_CERT", e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
            } catch (TokenException e) {
                mKRA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_CERT", e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
            } catch (ObjectNotFoundException e) {
                mKRA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_CERT", e.toString()));
                // XXX - this import wont work
                try {
                    mCert = mManager.importCertPackage(certData,
                                "kraStorageCert");
                } catch (Exception ex) {
                    mKRA.log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_KRA_STORAGE_IMPORT_CERT", e.toString()));
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", ex.toString()));
                }
            } finally {
                if (fi != null) {
                    try {
                        fi.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

            if (mKeySplitting) {
                // read private key from the file
                try {
                    File priFile = new File(mConfig.getString(PROP_KEYDB));

                    mPrivateKeyData = new byte[
                            (Long.valueOf(priFile.length())).intValue()];
                    fi = new FileInputStream(priFile);

                    fi.read(mPrivateKeyData);

                } catch (IOException e) {
                    mKRA.log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_PRIVATE", e.toString()));
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1", e.toString()));
                } finally {
                    if (fi != null) {
                        try {
                            fi.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }

        }

        if (mKeySplitting) {
            // open internal data storage configuration
            mTokenFile = mConfig.getString(PROP_MN);
            try {
                // read m, n and no of identifier
                mStorageConfig = CMS.createFileConfigStore(mTokenFile);
            } catch (EBaseException e) {
                mKRA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_MN",
                                e.toString()));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));

            }
        }

        try {
            if (mCert == null) {
                CMS.debug("mCert is null...retrieving " + config.getString(PROP_NICKNAME));
                mCert = mManager.findCertByNickname(
                           config.getString(PROP_NICKNAME));
                CMS.debug("mCert = " + mCert);
            }
        } catch (Exception e) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_STORAGE_READ_CERT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }

    }

    /**
     * Starts up this subsystem.
     */
    public void startup() throws EBaseException {
    }

    /**
     * Shutdowns this subsystem.
     */
    public void shutdown() {
    }

    /**
     * Returns the configuration store of this token.
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public static SymmetricKey buildSymmetricKeyWithInternalStorage(
            String pin) throws EBaseException {
        try {
            return buildSymmetricKey(CryptoManager.getInstance().getInternalKeyStorageToken(), pin);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Builds symmetric key from the given password.
     */
    public static SymmetricKey buildSymmetricKey(CryptoToken token,
            String pin) throws EBaseException {
        try {

            Password pass = new Password(pin.toCharArray());
            KeyGenerator kg = null;

            kg = token.getKeyGenerator(
                        PBEAlgorithm.PBE_SHA1_DES3_CBC);
            byte salt[] = { 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01 };
            PBEKeyGenParams kgp = new PBEKeyGenParams(pass,
                    salt, 5);

            pass.clear();
            kg.initialize(kgp);
            return kg.generate();
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "buildSymmetricKey:" +
                                e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "buildSymmetricKey:" +
                                e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "buildSymmetricKey:" +
                                e.toString()));
        } catch (CharConversionException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "buildSymmetricKey:" +
                                e.toString()));
        }
    }

    /**
     * Unwraps the storage key with the given symmetric key.
     */
    public PrivateKey unwrapStorageKey(CryptoToken token,
            SymmetricKey sk, byte wrapped[],
            PublicKey pubKey)
            throws EBaseException {
        try {

            CMS.debug("StorageKeyUnit.unwrapStorageKey.");

            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            wrapper.initUnwrap(sk, IV);

            // XXX - it does not like the public key that is
            // not a crypto X509Certificate
            PrivateKey pk = wrapper.unwrapTemporaryPrivate(wrapped,
                    PrivateKey.RSA, pubKey);

            return pk;
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "unwrapStorageKey:" +
                                e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "unwrapStorageKey:" +
                                e.toString()));
        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "unwrapStorageKey:" +
                                e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "unwrapStorageKey:" +
                                e.toString()));
        }
    }

    /**
     * Used by config-cert.
     */
    public byte[] wrapStorageKey(CryptoToken token,
            SymmetricKey sk, PrivateKey pri)
            throws EBaseException {
        CMS.debug("StorageKeyUnit.wrapStorageKey.");
        try {
            // move public & private to config/storage.dat
            // delete private key
            KeyWrapper wrapper = token.getKeyWrapper(
                    KeyWrapAlgorithm.DES3_CBC_PAD);

            // next to randomly generate a symmetric
            // password

            wrapper.initWrap(sk, IV);
            return wrapper.wrap(pri);
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "wrapStorageKey:" +
                                e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "wrapStorageKey:" +
                                e.toString()));
        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "wrapStorageKey:" +
                                e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        "wrapStorageKey:" +
                                e.toString()));
        }
    }

    /**
     * Logins to this token.
     */
    public void login(String pin) throws EBaseException {
        if (mConfig.getString(PROP_HARDWARE, null) != null) {
            try {
                getToken().login(new Password(pin.toCharArray()));
                PrivateKey pk[] = getToken().getCryptoStore().getPrivateKeys();

                for (int i = 0; i < pk.length; i++) {
                    if (arraysEqual(pk[i].getUniqueID(),
                            ((TokenCertificate) mCert).getUniqueID())) {
                        mPrivateKey = pk[i];
                    }
                }
            } catch (Exception e) {
                mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_STORAGE_LOGIN", e.toString()));
            }

        } else {
            try {
                SymmetricKey sk = buildSymmetricKey(mToken, pin);

                mPrivateKey = unwrapStorageKey(mToken, sk,
                            mPrivateKeyData, getPublicKey());
            } catch (Exception e) {
                mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_STORAGE_LOGIN", e.toString()));
            }
            if (mPrivateKey == null) {
                mPrivateKey = getPrivateKey();
            }
        }
    }

    /**
     * Logins to this token.
     */
    public void login(Credential creds[])
            throws EBaseException {
        String pwd = constructPassword(creds);

        login(pwd);
    }

    /**
     * Logout from this token.
     */
    public void logout() {
        try {
            if (mConfig.getString(PROP_HARDWARE, null) != null) {
                if (mConfig.getBoolean(PROP_LOGOUT, false)) {
                    getToken().logout();
                }
            }
        } catch (Exception e) {
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_STORAGE_LOGOUT", e.toString()));

        }
        mPrivateKey = null;
    }

    /**
     * Returns a list of recovery agent identifiers.
     */
    public Enumeration<String> getAgentIdentifiers() {
        Vector<String> v = new Vector<String>();

        for (int i = 0;; i++) {
            try {
                String uid =
                        mStorageConfig.getString(PROP_UID + i);

                if (uid == null)
                    break;
                v.addElement(uid);
            } catch (EBaseException e) {
                break;
            }
        }
        return v.elements();
    }

    /**
     * Changes agent password.
     */
    public boolean changeAgentPassword(String id, String oldpwd,
            String newpwd) throws EBaseException {
        // locate the id(s)
        for (int i = 0;; i++) {
            try {
                String uid =
                        mStorageConfig.getString(PROP_UID + i);

                if (uid == null)
                    break;
                if (id.equals(uid)) {
                    byte share[] = decryptShareWithInternalStorage(mStorageConfig.getString(PROP_SHARE + i), oldpwd);

                    mStorageConfig.putString(PROP_SHARE + i,
                            encryptShareWithInternalStorage(
                                    share, newpwd));
                    mStorageConfig.commit(false);
                    return true;
                }
            } catch (Exception e) {
                break;
            }
        }
        return false;
    }

    /**
     * Changes the m out of n recovery schema.
     */
    public boolean changeAgentMN(int new_n, int new_m,
            Credential oldcreds[],
            Credential newcreds[])
            throws EBaseException {

        if (new_n != newcreds.length) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_INVALID_N"));
        }

        // XXX - verify and construct original password
        String secret = constructPassword(oldcreds);

        // XXX - remove extra configuration
        for (int j = new_n; j < getNoOfAgents(); j++) {
            mStorageConfig.remove(PROP_UID + j);
            mStorageConfig.remove(PROP_SHARE + j);
        }

        // XXX - split pwd into n pieces
        byte shares[][] = new byte[newcreds.length][];

        IShare s = null;
        try {
            String className = mConfig.getString("share_class",
                                       "com.netscape.cms.shares.OldShare");
            s = (IShare) Class.forName(className).newInstance();
        } catch (Exception e) {
            CMS.debug("Loading Shares error " + e);
        }
        if (s == null) {
            CMS.debug("Share plugin is not found");
            return false;
        }

        try {
            s.initialize(secret.getBytes(), new_m);
        } catch (Exception e) {
            CMS.debug("Failed to initialize Share plugin");
            return false;
        }

        for (int i = 0; i < newcreds.length; i++) {
            byte share[] = s.createShare(i + 1);

            shares[i] = share;
        }

        // store the new shares into configuration
        mStorageConfig.putInteger(PROP_N, new_n);
        mStorageConfig.putInteger(PROP_M, new_m);
        for (int i = 0; i < newcreds.length; i++) {
            mStorageConfig.putString(PROP_UID + i,
                    newcreds[i].getIdentifier());
            // use password to encrypt shares...
            mStorageConfig.putString(PROP_SHARE + i,
                    encryptShareWithInternalStorage(shares[i],
                            newcreds[i].getPassword()));
        }

        try {
            mStorageConfig.commit(false);
            return true;
        } catch (EBaseException e) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_STORAGE_CHANGE_MN", e.toString()));
        }
        return false;
    }

    /**
     * Returns number of recovery agents.
     */
    public int getNoOfAgents() throws EBaseException {
        return mStorageConfig.getInteger(PROP_N);
    }

    /**
     * Returns number of recovery agents required for
     * recovery operation.
     */
    public int getNoOfRequiredAgents() throws EBaseException {
        return mStorageConfig.getInteger(PROP_M);
    }

    public void setNoOfRequiredAgents(int number) {
        mStorageConfig.putInteger(PROP_M, number);
    }

    public CryptoToken getInternalToken() {
        try {
            return CryptoManager.getInstance().getInternalKeyStorageToken();
        } catch (Exception e) {
            return null;
        }
    }

    public CryptoToken getToken() {
        try {
            if (mConfig.getString(PROP_HARDWARE, null) != null) {
                return mManager.getTokenByName(mConfig.getString(PROP_HARDWARE));
            } else {
                return CryptoManager.getInstance().getInternalKeyStorageToken();
            }
        } catch (Exception e) {
            return null;
        }
    }

    public CryptoToken getToken(org.mozilla.jss.crypto.X509Certificate cert) {
        return getToken();
    }

    /**
     * Returns the certificate blob.
     */
    public PublicKey getPublicKey() {
        // NEED to move this key into internal storage token.
        return mCert.getPublicKey();
    }

    public PrivateKey getPrivateKey() {

        if (!mKeySplitting) {
            try {
                PrivateKey pk[] = getToken().getCryptoStore().getPrivateKeys();
                for (int i = 0; i < pk.length; i++) {
                    if (arraysEqual(pk[i].getUniqueID(),
                            ((TokenCertificate) mCert).getUniqueID())) {
                        return pk[i];
                    }
                }
            } catch (TokenException e) {
            }
            return null;
        } else {
            return mPrivateKey;
        }
    }

    public PrivateKey getPrivateKey(org.mozilla.jss.crypto.X509Certificate cert) {
        return getPrivateKey();
    }

    /**
     * Verifies the integrity of the given key pairs.
     */
    public void verify(byte publicKey[], PrivateKey privateKey)
            throws EBaseException {
        // XXX
    }

    public String encryptShareWithInternalStorage(
            byte share[], String pwd)
            throws EBaseException {
        try {
            return encryptShare(CryptoManager.getInstance().getInternalKeyStorageToken(), share, pwd);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Protectes the share with the given password.
     */
    public String encryptShare(CryptoToken token,
            byte share[], String pwd)
            throws EBaseException {
        try {
            CMS.debug("StorageKeyUnit.encryptShare");
            Cipher cipher = token.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD);
            SymmetricKey sk = StorageKeyUnit.buildSymmetricKey(token, pwd);

            cipher.initEncrypt(sk, IV);
            byte prev[] = preVerify(share);
            byte enc[] = cipher.doFinal(prev);

            return Utils.base64encode(enc).trim();
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        e.toString()));
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        e.toString()));
        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        e.toString()));
        } catch (BadPaddingException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        e.toString()));
        } catch (IllegalBlockSizeException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1",
                        e.toString()));
        }
    }

    public static byte[] preVerify(byte share[]) {
        byte data[] = new byte[share.length + 2];

        data[0] = 0;
        data[1] = 0;
        for (int i = 0; i < share.length; i++) {
            data[2 + i] = share[i];
        }
        return data;
    }

    public static boolean verifyShare(byte share[]) {
        if (share[0] == 0 && share[1] == 0) {
            return true;
        } else {
            return false;
        }
    }

    public static byte[] postVerify(byte share[]) {
        byte data[] = new byte[share.length - 2];

        for (int i = 2; i < share.length; i++) {
            data[i - 2] = share[i];
        }
        return data;
    }

    public void checkPassword(String userid, String pwd) throws EBaseException {
        for (int i = 0;; i++) {
            String uid = null;

            try {
                uid = mStorageConfig.getString(PROP_UID + i);
                if (uid == null)
                    break;
            } catch (Exception e) {
                break;
            }
            if (uid.equals(userid)) {
                byte data[] = decryptShareWithInternalStorage(
                        mStorageConfig.getString(PROP_SHARE + i),
                        pwd);
                if (data == null) {
                    throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                }
                return;
            }
        }
        throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

    }

    public byte[] decryptShareWithInternalStorage(
            String encoding, String pwd)
            throws EBaseException {
        try {
            return decryptShare(CryptoManager.getInstance().getInternalKeyStorageToken(), encoding, pwd);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Decrypts shares with the given password.
     */
    public byte[] decryptShare(CryptoToken token,
            String encoding, String pwd)
            throws EBaseException {
        try {
            CMS.debug("StorageKeyUnit.decryptShare");
            byte share[] = CMS.AtoB(encoding);
            Cipher cipher = token.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD);
            SymmetricKey sk = StorageKeyUnit.buildSymmetricKey(
                    token, pwd);

            cipher.initDecrypt(sk, IV);
            byte dec[] = cipher.doFinal(share);

            if (dec == null || !verifyShare(dec)) {
                // invalid passwod
                throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            return postVerify(dec);
        } catch (OutOfMemoryError e) {
            // XXX - this happens in cipher.doFinal when
            // the given share is not valid (the password
            // given from the agent is not correct).
            // Actulla, cipher.doFinal should return
            // something better than this!
            //
            // e.printStackTrace();
            //
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        } catch (IllegalBlockSizeException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        } catch (BadPaddingException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        e.toString()));
        }
    }

    /**
     * Reconstructs password from recovery agents.
     */
    private String constructPassword(Credential creds[])
            throws EBaseException {
        // sort the credential according to the order in
        // configuration file
        Hashtable<String, byte[]> v = new Hashtable<String, byte[]>();

        for (int i = 0;; i++) {
            String uid = null;

            try {
                uid = mStorageConfig.getString(PROP_UID + i);
                if (uid == null)
                    break;
            } catch (Exception e) {
                break;
            }
            for (int j = 0; j < creds.length; j++) {
                if (uid.equals(creds[j].getIdentifier())) {
                    byte pwd[] = decryptShareWithInternalStorage(
                            mStorageConfig.getString(
                                    PROP_SHARE + i),
                            creds[j].getPassword());
                    if (pwd == null) {
                        throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                    }
                    v.put(Integer.toString(i), pwd);
                    break;
                }
            }
        }

        if (v.size() < 0) {
            throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        if (v.size() != creds.length) {
            throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        IJoinShares j = null;
        try {
            String className = mConfig.getString("joinshares_class",
                                       "com.netscape.cms.shares.OldJoinShares");
            j = (IJoinShares) Class.forName(className).newInstance();
        } catch (Exception e) {
            CMS.debug("JoinShares error " + e);
        }
        if (j == null) {
            CMS.debug("JoinShares plugin is not found");
            throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        try {
            j.initialize(v.size());
        } catch (Exception e) {
            CMS.debug("Failed to initialize JoinShares");
            throw new EBaseException(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }
        Enumeration<String> e = v.keys();

        while (e.hasMoreElements()) {
            String next = e.nextElement();

            j.addShare(Integer.parseInt(next) + 1, v.get(next));
        }
        try {
            byte secret[] = j.recoverSecret();
            String pwd = new String(secret);

            return pwd;
        } catch (Exception ee) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_STORAGE_RECONSTRUCT", e.toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_PASSWORD",
                        ee.toString()));
        }
    }

    public static boolean arraysEqual(byte[] bytes, byte[] ints) {
        if (bytes == null || ints == null) {
            return false;
        }

        if (bytes.length != ints.length) {
            return false;
        }

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != ints[i]) {
                return false;
            }
        }
        return true;
    }

}
