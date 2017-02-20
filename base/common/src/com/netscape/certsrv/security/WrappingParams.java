package com.netscape.certsrv.security;

import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKey.Type;
import org.mozilla.jss.crypto.SymmetricKey.Usage;

public class WrappingParams {
    // session key attributes
    SymmetricKey.Type skTyoe;
    SymmetricKey.Usage[] skUsages;
    KeyGenAlgorithm skKeyGenAlgorithm;
    int skLength;

    // wrapping algorithm for session key
    KeyWrapAlgorithm skWrapAlgorithm;

    // Encryption algorithm for payload
    EncryptionAlgorithm payloadEncryptionAlgorithm;

    //wrapping algorithm for payload
    KeyWrapAlgorithm payloadWrapAlgorithm;

    public WrappingParams(Type skTyoe, Usage[] skUsages, KeyGenAlgorithm skKeyGenAlgorithm, int skLength,
            KeyWrapAlgorithm skWrapAlgorithm, EncryptionAlgorithm payloadEncryptionAlgorithm,
            KeyWrapAlgorithm payloadWrapAlgorithm) {
        super();
        this.skTyoe = skTyoe;
        this.skUsages = skUsages;
        this.skKeyGenAlgorithm = skKeyGenAlgorithm;
        this.skLength = skLength;
        this.skWrapAlgorithm = skWrapAlgorithm;
        this.payloadEncryptionAlgorithm = payloadEncryptionAlgorithm;
        this.payloadWrapAlgorithm = payloadWrapAlgorithm;
    }

    public SymmetricKey.Type getSkTyoe() {
        return skTyoe;
    }

    public void setSkTyoe(SymmetricKey.Type skTyoe) {
        this.skTyoe = skTyoe;
    }

    public SymmetricKey.Usage[] getSkUsages() {
        return skUsages;
    }

    public void setSkUsages(SymmetricKey.Usage[] skUsages) {
        this.skUsages = skUsages;
    }

    public KeyGenAlgorithm getSkKeyGenAlgorithm() {
        return skKeyGenAlgorithm;
    }

    public void setSkKeyGenAlgorithm(KeyGenAlgorithm skKeyGenAlgorithm) {
        this.skKeyGenAlgorithm = skKeyGenAlgorithm;
    }

    public int getSkLength() {
        return skLength;
    }

    public void setSkLength(int skLength) {
        this.skLength = skLength;
    }

    public KeyWrapAlgorithm getSkWrapAlgorithm() {
        return skWrapAlgorithm;
    }

    public void setSkWrapAlgorithm(KeyWrapAlgorithm skWrapAlgorithm) {
        this.skWrapAlgorithm = skWrapAlgorithm;
    }

    public EncryptionAlgorithm getPayloadEncryptionAlgorithm() {
        return payloadEncryptionAlgorithm;
    }

    public void setPayloadEncryptionAlgorithm(EncryptionAlgorithm payloadEncryptionAlgorithm) {
        this.payloadEncryptionAlgorithm = payloadEncryptionAlgorithm;
    }

    public KeyWrapAlgorithm getPayloadWrapAlgorithm() {
        return payloadWrapAlgorithm;
    }

    public void setPayloadWrapAlgorithm(KeyWrapAlgorithm payloadWrapAlgorithm) {
        this.payloadWrapAlgorithm = payloadWrapAlgorithm;
    }
}
