package com.netscape.certsrv.util;

import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;

/**
 * An abstract class defining the functionality to be provided by
 * sub classes to perform cryptographic operations.
 *
 * @author akoneru
 *
 */
public abstract class CryptoProvider {

    public abstract void initialize() throws Exception;

    public abstract SymmetricKey generateSymmetricKey(String keyAlgorithm, int keySize) throws Exception;

    public abstract SymmetricKey generateSessionKey() throws Exception;

    public abstract byte[] wrapSessionKeyWithTransportCert(SymmetricKey sessionKey, String transportCert)
            throws Exception;

    public abstract byte[] wrapWithSessionKey(String passphrase, byte[] iv, SymmetricKey key, String keyAlgorithm)
            throws Exception;

    public abstract byte[] wrapWithSessionKey(String passphrase, byte[] iv, SymmetricKey key, EncryptionAlgorithm keyAlgorithm)
            throws Exception;

    public abstract byte[] wrapWithSessionKey(SymmetricKey secret, SymmetricKey sessionKey, byte[] iv) throws Exception;

    public abstract byte[] wrapWithSessionKey(SymmetricKey secret, SymmetricKey sessionKey, byte[] iv,
            KeyWrapAlgorithm wrapAlg) throws Exception;

    public abstract byte[] unwrapWithSessionKey(byte[] wrappedRecoveredKey, SymmetricKey recoveryKey,
            String keyAlgorithm, byte[] nonceData) throws Exception;

    public abstract byte[] unwrapWithSessionKey(byte[] wrappedRecoveredKey, SymmetricKey recoveryKey,
            EncryptionAlgorithm keyAlgorithm, byte[] nonceData) throws Exception;

    public abstract byte[] unwrapWithPassphrase(byte[] wrappedRecoveredKey, String recoveryPassphrase)
            throws Exception;

    public abstract byte[] createPKIArchiveOptions(String transportCert, SymmetricKey secret, String passphrase,
            String keyAlgorithm, int symKeySize, byte[] nonceData) throws Exception;

}
