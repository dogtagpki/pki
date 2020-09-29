package com.netscape.certsrv.util;

import java.security.PublicKey;

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

    public abstract SymmetricKey generateSessionKey(EncryptionAlgorithm algorithm) throws Exception;

    public abstract byte[] wrapSymmetricKey(SymmetricKey symmetricKey, PublicKey wrappingKey)
            throws Exception;

    public abstract byte[] encryptSecret(byte[] secret, byte[] iv, SymmetricKey key, String keyAlgorithm)
            throws Exception;

    public abstract byte[] encryptSecret(byte[] secret, byte[] iv, SymmetricKey key, EncryptionAlgorithm keyAlgorithm)
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

    public abstract byte[] unwrapSymmetricKeyWithSessionKey(byte[] wrappedRecoveredKey, SymmetricKey recoveryKey,
            KeyWrapAlgorithm wrapAlgorithm, byte[] nonceData, String algorithm, int size)
            throws Exception;

    public abstract byte[] unwrapAsymmetricKeyWithSessionKey(byte[] wrappedRecoveredKey, SymmetricKey recoveryKey,
            KeyWrapAlgorithm wrapAlgorithm, byte[] nonceData, PublicKey pubKey)
            throws Exception;

}
