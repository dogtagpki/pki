package com.netscape.certsrv.util;

import org.mozilla.jss.crypto.SymmetricKey;

public abstract class CryptoProvider {

    public abstract void initialize() throws Exception;

    public abstract SymmetricKey generateSymmetricKey(String keyAlgorithm, int keySize) throws Exception;

    public abstract SymmetricKey generateSessionKey() throws Exception;

    public abstract byte[] wrapSessionKeyWithTransportCert(SymmetricKey sessionKey, String transportCert)
            throws Exception;

    public abstract byte[] wrapUsingSessionKey(String passphrase, byte[] iv, SymmetricKey key, String keyAlgorithm)
            throws Exception;

    public abstract String unwrapUsingSessionKey(byte[] wrappedRecoveredKey, SymmetricKey recoveryKey,
            String keyAlgorithm, byte[] nonceData) throws Exception;

    public abstract String unWrapUsingPassphrase(String wrappedRecoveredKey, String recoveryPassphrase)
            throws Exception;

}
