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
// Copyright (C) 2025 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools;

import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.asn1.BIT_STRING;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * CryptoToolsUtil - Shared cryptographic utility methods for PKI tools
 *
 * This class provides common cryptographic operations needed by various tools
 * in the com.netscape.cmstools package, allowing them to remain self-contained
 * without requiring changes to pki-common.
 *
 * These methods are primarily adapted from CryptoUtil to support standalone
 * tool builds with minimal dependencies.
 */
public class CryptoToolsUtil {

    private static final SymmetricKey.Usage[] SESSION_KEY_USAGES = {
        SymmetricKey.Usage.WRAP, SymmetricKey.Usage.UNWRAP,
        SymmetricKey.Usage.ENCRYPT, SymmetricKey.Usage.DECRYPT
    };

    /**
     * Container for PKIArchiveOptions and the wrapped key data.
     * Useful for testing and diagnostics where you need access to the raw wrapped keys.
     */
    public static class PKIArchiveOptionsData {
        public final PKIArchiveOptions options;
        public final byte[] wrappedPrivateKey;
        public final byte[] wrappedSessionKey;

        public PKIArchiveOptionsData(PKIArchiveOptions options, byte[] wrappedPrivateKey, byte[] wrappedSessionKey) {
            this.options = options;
            this.wrappedPrivateKey = wrappedPrivateKey;
            this.wrappedSessionKey = wrappedSessionKey;
        }
    }

    /**
     * Create PKIArchiveOptions with separate access to wrapped key data.
     *
     * This method performs the complete key archival wrapping process:
     * 1. Generates a session key (symmetric key for wrapping the private key)
     * 2. Wraps the private key using the session key
     * 3. Wraps the session key using the transport public key (RSA)
     * 4. Packages everything into PKIArchiveOptions ASN.1 structure
     *
     * @param token CryptoToken to use for cryptographic operations
     * @param wrappingKey Public key (KRA transport cert) to wrap the session key
     * @param privKey Private key to be archived
     * @param params Wrapping parameters (algorithms, key sizes, IVs)
     * @param aid Algorithm identifier for the payload wrapping algorithm
     * @return PKIArchiveOptionsData containing the ASN.1 structure and raw wrapped keys
     * @throws Exception if any cryptographic operation fails
     */
    public static PKIArchiveOptionsData createPKIArchiveOptionsWithData(
            CryptoToken token,
            PublicKey wrappingKey,
            org.mozilla.jss.crypto.PrivateKey privKey,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        // Generate session key for wrapping the private key
        SymmetricKey sessionKey = CryptoUtil.generateKey(
                token,
                params.getSkKeyGenAlgorithm(),
                params.getSkLength(),
                SESSION_KEY_USAGES,
                true, cm.FIPSEnabled() /* sensitive */);

        // Wrap private key with session key
        byte[] wrappedPrivateKey = wrapUsingSymmetricKey(
                token,
                sessionKey,
                privKey,
                params.getPayloadWrappingIV(),
                params.getPayloadWrapAlgorithm());

        // Wrap session key with transport public key
        byte[] wrappedSessionKey = wrapUsingPublicKey(
                token,
                wrappingKey,
                sessionKey,
                params.getSkWrapAlgorithm());

        // Create PKIArchiveOptions ASN.1 structure
        PKIArchiveOptions options = createPKIArchiveOptions(wrappedSessionKey, wrappedPrivateKey, aid);

        return new PKIArchiveOptionsData(options, wrappedPrivateKey, wrappedSessionKey);
    }

    /**
     * Wrap a private key using a symmetric key.
     *
     * @param token CryptoToken to use for the operation
     * @param wrappingKey Symmetric key to use for wrapping
     * @param data Private key to wrap
     * @param ivspec Initialization vector (for CBC mode algorithms)
     * @param alg Key wrap algorithm (e.g., AES_CBC_PAD, AES_KEY_WRAP_PAD_KWP)
     * @return Wrapped private key as byte array
     * @throws Exception if wrapping fails
     */
    public static byte[] wrapUsingSymmetricKey(
            CryptoToken token,
            SymmetricKey wrappingKey,
            org.mozilla.jss.crypto.PrivateKey data,
            IVParameterSpec ivspec,
            KeyWrapAlgorithm alg) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(alg);
        wrapper.initWrap(wrappingKey, ivspec);
        return wrapper.wrap(data);
    }

    /**
     * Wrap a symmetric key using a public key (RSA).
     *
     * @param token CryptoToken to use for the operation
     * @param wrappingKey RSA public key to use for wrapping
     * @param data Symmetric key to wrap
     * @param alg Key wrap algorithm (RSA or RSA_OAEP)
     * @return Wrapped symmetric key as byte array
     * @throws Exception if wrapping fails
     */
    public static byte[] wrapUsingPublicKey(
            CryptoToken token,
            PublicKey wrappingKey,
            SymmetricKey data,
            KeyWrapAlgorithm alg) throws Exception {
        KeyWrapper rsaWrap = token.getKeyWrapper(alg);
        if (alg.equals(KeyWrapAlgorithm.RSA_OAEP)) {
            OAEPParameterSpec config = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsaWrap.initWrap(wrappingKey, config);
        } else {
            rsaWrap.initWrap(wrappingKey, null);
        }
        return rsaWrap.wrap(data);
    }

    /**
     * Create PKIArchiveOptions from pre-wrapped key data.
     *
     * This is a lower-level method that creates the ASN.1 structure from
     * already-wrapped keys. Use createPKIArchiveOptionsWithData() for the
     * complete wrapping workflow.
     *
     * @param session_data Wrapped session key (encrypted with transport public key)
     * @param key_data Wrapped private key (encrypted with session key)
     * @param aid Algorithm identifier for the payload wrapping algorithm
     * @return PKIArchiveOptions ASN.1 structure
     */
    public static PKIArchiveOptions createPKIArchiveOptions(
            byte[] session_data,
            byte[] key_data,
            AlgorithmIdentifier aid) {
        // Create PKIArchiveOptions structure according to RFC 4211
        EncryptedValue encValue = new EncryptedValue(
                null,                              // intendedAlg (optional)
                aid,                               // symmAlg (algorithm for key_data)
                new BIT_STRING(session_data, 0),   // encSymmKey (wrapped session key)
                null,                              // keyAlg (optional)
                null,                              // valueHint (optional)
                new BIT_STRING(key_data, 0));      // encValue (wrapped private key)
        EncryptedKey key = new EncryptedKey(encValue);
        return new PKIArchiveOptions(key);
    }
}
