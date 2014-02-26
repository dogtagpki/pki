package com.netscape.certsrv.util;

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.IncorrectPasswordException;
import org.mozilla.jss.util.Password;

import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class NSSCryptoProvider extends CryptoProvider {

    private CryptoManager manager;
    private CryptoToken token;
    private File certDBDir;
    private String certDBPassword;

    public CryptoManager getManager() {
        return manager;
    }

    public void setManager(CryptoManager manager) {
        this.manager = manager;
    }

    public CryptoToken getToken() {
        return token;
    }

    public void setToken(CryptoToken token) {
        this.token = token;
    }

    public NSSCryptoProvider(ClientConfig config)
            throws Exception {
        if (config == null) {
            throw new IllegalArgumentException("ClientConfig object must be specified.");
        }
        if ((config.getCertDatabase() == null) || (config.getCertPassword() == null)) {
            throw new IllegalArgumentException(" Both the db directory path and the password must be specified.");
        }
        this.certDBDir = new File(config.getCertDatabase());
        if (this.certDBDir.exists()) {
            if (!this.certDBDir.isDirectory())
                throw new IllegalArgumentException("Cert database must be a directory.");
        }
        this.certDBDir.mkdir();
        this.certDBPassword = config.getCertPassword();
        initialize();
    }

    /**
     * Initializes the NSS DB.
     *
     */
    @Override
    public void initialize() throws Exception {
        if ((certDBDir == null) || (certDBPassword == null)) {
            throw new Exception("NSS db location and password need to be specified.");
        }
        try {
            CryptoManager.initialize(certDBDir.getAbsolutePath());
        } catch (AlreadyInitializedException e) {
            // Can be ignored since it is just for getting the token
        } catch (KeyDatabaseException | CertDatabaseException | GeneralSecurityException e1) {
            throw e1;
        }
        try {
            manager = CryptoManager.getInstance();
            token = manager.getInternalKeyStorageToken();
            Password password = new Password(certDBPassword.toCharArray());
            try {
                token.login(password);
            } catch (IncorrectPasswordException | TokenException e) {
                if (!token.isLoggedIn()) {
                    token.initPassword(password, password);
                }
            }
        } catch (AlreadyInitializedException e1) {
            //Ignore
        } catch (NotInitializedException | TokenException | IncorrectPasswordException e2) {
            throw e2;
        }
    }

    @Override
    public SymmetricKey generateSymmetricKey(String keyAlgorithm, int keySize) throws Exception {
        if (token == null) {
            throw new NotInitializedException();
        }
        return CryptoUtil.generateKey(token, getKeyGenAlgorithm(keyAlgorithm), keySize);
    }

    @Override
    public SymmetricKey generateSessionKey() throws Exception {
        return generateSymmetricKey(KeyRequestResource.DES3_ALGORITHM, 168);
    }

    @Override
    public byte[] wrapSessionKeyWithTransportCert(SymmetricKey sessionKey, String transportCert) throws Exception {
        if ((manager == null) || (token == null)) {
            throw new NotInitializedException();
        }
        return CryptoUtil.wrapSymmetricKey(manager, token, transportCert, sessionKey);
    }

    @Override
    public byte[] wrapUsingSessionKey(String passphrase, byte[] iv, SymmetricKey key, String encryptionAlgorithm)
            throws Exception {
        if (token == null) {
            throw new NotInitializedException();
        }
        return CryptoUtil.wrapPassphrase(token, passphrase, new IVParameterSpec(iv), key,
                getEncryptionAlgorithm(encryptionAlgorithm));
    }

    @Override
    public String unwrapUsingSessionKey(byte[] wrappedRecoveredKey, SymmetricKey recoveryKey,
            String encryptionAlgorithm, byte[] nonceData) throws Exception {
        if (token == null) {
            throw new NotInitializedException();
        }
        return CryptoUtil.unwrapUsingSymmetricKey(token, new IVParameterSpec(nonceData), wrappedRecoveredKey,
                recoveryKey,
                getEncryptionAlgorithm(encryptionAlgorithm));
    }

    @Override
    public String unWrapUsingPassphrase(String wrappedRecoveredKey, String recoveryPassphrase) throws Exception {
        return CryptoUtil.unwrapUsingPassphrase(wrappedRecoveredKey, recoveryPassphrase);
    }

    public KeyGenAlgorithm getKeyGenAlgorithm(String keyAlgorithm) throws NoSuchAlgorithmException {
        if (keyAlgorithm == null) {
            return KeyGenAlgorithm.DES3;
        }
        KeyGenAlgorithm alg = null;
        switch (keyAlgorithm) {
        case KeyRequestResource.AES_ALGORITHM:
            alg = KeyGenAlgorithm.AES;
            break;
        case KeyRequestResource.DES_ALGORITHM:
            alg = KeyGenAlgorithm.DES;
            break;
        case KeyRequestResource.DESEDE_ALGORITHM:
            alg = KeyGenAlgorithm.DESede;
            break;
        case KeyRequestResource.RC2_ALGORITHM:
            alg = KeyGenAlgorithm.RC2;
            break;
        case KeyRequestResource.RC4_ALGORITHM:
            alg = KeyGenAlgorithm.RC4;
            break;
        case KeyRequestResource.DES3_ALGORITHM:
            alg = KeyGenAlgorithm.DES3;
            break;
        default:
            throw new NoSuchAlgorithmException("No Algorithm named: " + keyAlgorithm);
        }
        return alg;
    }

    public EncryptionAlgorithm getEncryptionAlgorithm(String encryptionAlgorithm) throws NoSuchAlgorithmException {
        if (encryptionAlgorithm == null) {
            return EncryptionAlgorithm.DES3_CBC_PAD;
        }
        EncryptionAlgorithm alg = null;
        switch (encryptionAlgorithm) {
        case KeyRequestResource.AES_ALGORITHM:
            alg = EncryptionAlgorithm.AES_CBC_PAD;
            break;
        case KeyRequestResource.DES_ALGORITHM:
            alg = EncryptionAlgorithm.DES_CBC_PAD;
            break;
        case KeyRequestResource.RC2_ALGORITHM:
            alg = EncryptionAlgorithm.RC2_CBC_PAD;
            break;
        case KeyRequestResource.RC4_ALGORITHM:
            alg = EncryptionAlgorithm.RC4;
            break;
        case KeyRequestResource.DES3_ALGORITHM:
            alg = EncryptionAlgorithm.DES3_CBC_PAD;
            break;
        default:
            throw new NoSuchAlgorithmException("No Algorithm named: " + encryptionAlgorithm);
        }
        return alg;
    }

}
