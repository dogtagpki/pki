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
package com.netscape.cmsutil.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NicknameConflictException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.UserCertConflictException;
import org.mozilla.jss.SecretDecoderRing.KeyManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.NULL;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.TeletexString;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.asn1.UniversalString;
import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.PKCS9Attribute;
import org.mozilla.jss.netscape.security.pkcs.ParsingException;
import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.util.WrappingParams;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertAttrSet;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X500Signer;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs7.IssuerAndSerialNumber;
import org.mozilla.jss.pkcs7.RecipientInfo;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncryptedContentInfo;
import org.mozilla.jss.pkix.cms.EnvelopedData;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.ssl.SSLCipher;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.Base64OutputStream;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("serial")
public class CryptoUtil {

    private CryptoUtil () {/* Prevent instantiation */}

    private static Logger logger = LoggerFactory.getLogger(CryptoUtil.class);

    public static final int KEY_ID_LENGTH = 20;

    public static final String INTERNAL_TOKEN_NAME = "internal";
    public static final String INTERNAL_TOKEN_FULL_NAME = "Internal Key Storage Token";

    public static final int LINE_COUNT = 76;

    private static SymmetricKey.Usage[] sess_key_usages = {
            SymmetricKey.Usage.WRAP,
            SymmetricKey.Usage.UNWRAP,
            SymmetricKey.Usage.ENCRYPT,
            SymmetricKey.Usage.DECRYPT
    };

    // ECDHE needs SIGN but no DERIVE
    public static final KeyPairGeneratorSpi.Usage[] ECDHE_USAGES_MASK = {
            KeyPairGeneratorSpi.Usage.DERIVE
    };

    // ECDH needs DERIVE but no any kind of SIGN
    public static final KeyPairGeneratorSpi.Usage[] ECDH_USAGES_MASK = {
            KeyPairGeneratorSpi.Usage.SIGN,
            KeyPairGeneratorSpi.Usage.SIGN_RECOVER,
    };

    // nCipher (v. 12.60+) wrapping/unwrapping keys requirements
    public static final org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] RSA_KEYPAIR_USAGES = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.ENCRYPT,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DECRYPT,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.WRAP,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.UNWRAP,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
        };

    public static final org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] RSA_KEYPAIR_USAGES_MASK = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.ENCRYPT,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DECRYPT,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.WRAP,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.UNWRAP,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
        };

    public static final Integer[] clientECCiphers = {
            // SSLSocket.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            // SSLSocket.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            // SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            // SSLSocket.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            // SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            // SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            // SSLSocket.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    };
    public static List<Integer> clientECCipherList = new ArrayList<>(Arrays.asList(clientECCiphers));

    private static final String[] ecCurves = {
            "nistp256", "nistp384", "nistp521", "sect163k1", "nistk163", "sect163r1", "sect163r2",
            "nistb163", "sect193r1", "sect193r2", "sect233k1", "nistk233", "sect233r1", "nistb233", "sect239k1",
            "sect283k1", "nistk283",
            "sect283r1", "nistb283", "sect409k1", "nistk409", "sect409r1", "nistb409", "sect571k1", "nistk571",
            "sect571r1", "nistb571",
            "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "nistp192", "secp224k1", "secp224r1",
            "nistp224", "secp256k1",
            "secp256r1", "secp384r1", "secp521r1", "prime192v1", "prime192v2", "prime192v3", "prime239v1",
            "prime239v2", "prime239v3", "c2pnb163v1",
            "c2pnb163v2", "c2pnb163v3", "c2pnb176v1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2pnb208w1",
            "c2tnb239v1", "c2tnb239v2", "c2tnb239v3",
            "c2pnb272w1", "c2pnb304w1", "c2tnb359w1", "c2pnb368w1", "c2tnb431r1", "secp112r1", "secp112r2",
            "secp128r1", "secp128r2", "sect113r1", "sect113r2",
            "sect131r1", "sect131r2"
    };

    /* DES KEY Parity conversion table. Takes each byte >> 1 as an index, returns
     * that byte with the proper parity bit set*/
    private static final int parityTable[] =
    {
            /* Even...0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e */
            /* E */0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
            /* Odd....0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e */
            /* O */0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
            /* Odd....0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e */
            /* O */0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
            /* Even...0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e */
            /* E */0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e,
            /* Odd....0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e */
            /* O */0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f,
            /* Even...0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e */
            /* E */0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e,
            /* Even...0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e */
            /* E */0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e,
            /* Odd....0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e */
            /* O */0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f,
            /* Odd....0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e */
            /* O */0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f,
            /* Even...0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e */
            /* E */0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e,
            /* Even...0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae */
            /* E */0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae,
            /* Odd....0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe */
            /* O */0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf,
            /* Even...0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce */
            /* E */0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce,
            /* Odd....0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde */
            /* O */0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf,
            /* Odd....0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee */
            /* O */0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef,
            /* Even...0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe */
            /* E */0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe,
    };

    public static final Map<String, Vector<String>> ecOIDs = Map.ofEntries(
            Map.entry("1.2.840.10045.3.1.7", new Vector<>(List.of("nistp256", "secp256r1"))),
            Map.entry("1.3.132.0.34", new Vector<>(List.of("nistp384", "secp384r1"))),
            Map.entry("1.3.132.0.35", new Vector<>(List.of("nistp521", "secp521r1"))),
            Map.entry("1.3.132.0.1", new Vector<>(List.of("sect163k1", "nistk163"))),
            Map.entry("1.3.132.0.2", new Vector<>(List.of("sect163r1"))),
            Map.entry("1.3.132.0.15", new Vector<>(List.of("sect163r2", "nistb163"))),
            Map.entry("1.3.132.0.24", new Vector<>(List.of("sect193r1"))),
            Map.entry("1.3.132.0.25", new Vector<>(List.of("sect193r2"))),
            Map.entry("1.3.132.0.26", new Vector<>(List.of("sect233k1", "nistk233"))),
            Map.entry("1.3.132.0.27", new Vector<>(List.of("sect233r1", "nistb233"))),
            Map.entry("1.3.132.0.3", new Vector<>(List.of("sect239k1"))),
            Map.entry("1.3.132.0.16", new Vector<>(List.of("sect283k1", "nistk283"))),
            Map.entry("1.3.132.0.17", new Vector<>(List.of("sect283r1", "nistb283"))),
            Map.entry("1.3.132.0.36", new Vector<>(List.of("sect409k1", "nistk409"))),
            Map.entry("1.3.132.0.37", new Vector<>(List.of("sect409r1", "nistb409"))),
            Map.entry("1.3.132.0.38", new Vector<>(List.of("sect571k1", "nistk571"))),
            Map.entry("1.3.132.0.39", new Vector<>(List.of("sect571r1", "nistb571"))),
            Map.entry("1.3.132.0.9", new Vector<>(List.of("secp160k1"))),
            Map.entry("1.3.132.0.8", new Vector<>(List.of("secp160r1"))),
            Map.entry("1.3.132.0.30", new Vector<>(List.of("secp160r2"))),
            Map.entry("1.3.132.0.31", new Vector<>(List.of("secp192k1"))),
            Map.entry("1.2.840.10045.3.1.1", new Vector<>(List.of("secp192r1", "nistp192", "prime192v1"))),
            Map.entry("1.3.132.0.32", new Vector<>(List.of("secp224k1"))),
            Map.entry("1.3.132.0.33", new Vector<>(List.of("secp224r1", "nistp224"))),
            Map.entry("1.3.132.0.10", new Vector<>(List.of("secp256k1"))),
            Map.entry("1.2.840.10045.3.1.2", new Vector<>(List.of("prime192v2"))),
            Map.entry("1.2.840.10045.3.1.3", new Vector<>(List.of("prime192v3"))),
            Map.entry("1.2.840.10045.3.1.4", new Vector<>(List.of("prime239v1"))),
            Map.entry("1.2.840.10045.3.1.5", new Vector<>(List.of("prime239v2"))),
            Map.entry("1.2.840.10045.3.1.6", new Vector<>(List.of("prime239v3"))),
            Map.entry("1.2.840.10045.3.0.1", new Vector<>(List.of("c2pnb163v1"))),
            Map.entry("1.2.840.10045.3.0.2", new Vector<>(List.of("c2pnb163v2"))),
            Map.entry("1.2.840.10045.3.0.3", new Vector<>(List.of("c2pnb163v3"))),
            Map.entry("1.2.840.10045.3.0.4", new Vector<>(List.of("c2pnb176v1"))),
            Map.entry("1.2.840.10045.3.0.5", new Vector<>(List.of("c2tnb191v1"))),
            Map.entry("1.2.840.10045.3.0.6", new Vector<>(List.of("c2tnb191v2"))),
            Map.entry("1.2.840.10045.3.0.7", new Vector<>(List.of("c2tnb191v3"))),
            Map.entry("1.2.840.10045.3.0.10", new Vector<>(List.of("c2pnb208w1"))),
            Map.entry("1.2.840.10045.3.0.11", new Vector<>(List.of("c2tnb239v1"))),
            Map.entry("1.2.840.10045.3.0.12", new Vector<>(List.of("c2tnb239v2"))),
            Map.entry("1.2.840.10045.3.0.13", new Vector<>(List.of("c2tnb239v3"))),
            Map.entry("1.2.840.10045.3.0.16", new Vector<>(List.of("c2pnb272w1"))),
            Map.entry("1.2.840.10045.3.0.17", new Vector<>(List.of("c2pnb304w1"))),
            Map.entry("1.2.840.10045.3.0.19", new Vector<>(List.of("c2pnb368w1"))),
            Map.entry("1.2.840.10045.3.0.20", new Vector<>(List.of("c2tnb431r1"))),
            Map.entry("1.3.132.0.6", new Vector<>(List.of("secp112r1"))),
            Map.entry("1.3.132.0.7", new Vector<>(List.of("secp112r2"))),
            Map.entry("1.3.132.0.28", new Vector<>(List.of("secp128r1"))),
            Map.entry("1.3.132.0.29", new Vector<>(List.of("secp128r2"))),
            Map.entry("1.3.132.0.4", new Vector<>(List.of("sect113r1"))),
            Map.entry("1.3.132.0.5", new Vector<>(List.of("sect113r2"))),
            Map.entry("1.3.132.0.22", new Vector<>(List.of("sect131r1"))),
            Map.entry("1.3.132.0.23", new Vector<>(List.of("sect131r2")))
        );

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

    public static boolean isInternalToken(String name) {
        return StringUtils.isEmpty(name)
                || name.equalsIgnoreCase(INTERNAL_TOKEN_NAME)
                || name.equalsIgnoreCase(INTERNAL_TOKEN_FULL_NAME);
    }

    /**
     * Retrieves handle to a crypto token.
     */
    public static CryptoToken getCryptoToken(String name)
            throws NotInitializedException, NoSuchTokenException {

        CryptoManager cm = CryptoManager.getInstance();

        if (isInternalToken(name)) {
            return cm.getInternalCryptoToken();
        }

        return cm.getTokenByName(name);
    }

    /**
     * Retrieves handle to a key store token.
     */
    public static CryptoToken getKeyStorageToken(String name)
            throws NotInitializedException, NoSuchTokenException {

        CryptoManager cm = CryptoManager.getInstance();

        if (isInternalToken(name)) {
            return cm.getInternalKeyStorageToken();
        }

        return cm.getTokenByName(name);
    }

    /**
     * Retrieves handle to a key store token.
     */
    public static Enumeration<CryptoToken> getExternalTokens()
            throws NotInitializedException, NoSuchTokenException {

        CryptoManager cm = CryptoManager.getInstance();

        return cm.getExternalTokens();
    }

    public static KeyPair generateRSAKeyPair(
            CryptoToken token,
            int keySize) throws Exception {

        return generateRSAKeyPair(
                token,
                keySize,
                null,
                null);
    }

    public static KeyPair generateRSAKeyPair(
            CryptoToken token,
            int keySize,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        return generateRSAKeyPair(
                token,
                keySize,
                null,
                null,
                null,
                usages,
                usagesMask);
    }

    /**
     * Generates an RSA key pair.
     */
    public static KeyPair generateRSAKeyPair(
            CryptoToken token,
            int keySize,
            Boolean temporary,
            Boolean sensitive,
            Boolean extractable,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        logger.debug("CryptoUtil: Generating KRA key pair");

        KeyPairGenerator keygen = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);

        logger.debug("CryptoUtil: - temporary: " + temporary);
        if (temporary != null) {
            keygen.temporaryPairs(temporary);
        }

        logger.debug("CryptoUtil: - sensitive: " + sensitive);
        if (sensitive != null) {
            keygen.sensitivePairs(sensitive);
        }

        logger.debug("CryptoUtil: - extractable: " + extractable);
        if (extractable != null) {
            keygen.extractablePairs(extractable);
        }

        String usageList = usages != null ? String.join(",", Stream.of(usages).map(org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage::name).toArray(String[]::new)) : "";
        logger.debug("CryptoUtil: generateRSAKeyPair with key usage {}", usageList);
        String usageMaskList = usagesMask != null ? String.join(",", Stream.of(usagesMask).map(org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage::name).toArray(String[]::new)) : "";
        logger.debug("CryptoUtil: generateRSAKeyPair with key usage mask {}", usageMaskList);
        keygen.setKeyPairUsages(usages, usagesMask);

        logger.debug("CryptoUtil: - key size: " + keySize);
        keygen.initialize(keySize);

        return keygen.genKeyPair();
    }

    public static boolean isECCKey(X509Key key) {
        String keyAlgo = key.getAlgorithm();
        if (keyAlgo.equals("EC") ||
                keyAlgo.equals("OID.1.2.840.10045.44")) { // ECC
            return true;
        }
        return false;
    }

    public static KeyPair generateECCKeyPair(
            CryptoToken token,
            String curveName) throws Exception {

        return generateECCKeyPair(
                token,
                curveName,
                null,
                null);
    }

    public static KeyPair generateECCKeyPair(
            CryptoToken token,
            String curveName,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        return generateECCKeyPair(
                token,
                curveName,
                null,
                null,
                null,
                usages,
                usagesMask);
    }

    /**
     * Generate an ECC key pair.
     *
     * temporary, sensitive, extractable, and usages are per defined in
     * JSS pkcs11/PK11KeyPairGenerator.java
     */
    public static KeyPair generateECCKeyPair(
            CryptoToken token,
            String curveName,
            Boolean temporary,
            Boolean sensitive,
            Boolean extractable,
            Usage[] usages,
            Usage[] usagesMask) throws Exception {

        logger.debug("CryptoUtil: Generating ECC key pair");

        KeyPairGenerator keygen = token.getKeyPairGenerator(KeyPairAlgorithm.EC);

        logger.debug("CryptoUtil: - curve: " + curveName);
        int curveCode = keygen.getCurveCodeByName(curveName);

        logger.debug("CryptoUtil: - temporary: " + temporary);
        if (temporary != null) {
            keygen.temporaryPairs(temporary);
        }

        logger.debug("CryptoUtil: - sensitive: " + sensitive);
        if (sensitive != null) {
            keygen.sensitivePairs(sensitive);
        }

        logger.debug("CryptoUtil: - extractable: " + extractable);
        if (extractable != null) {
            keygen.extractablePairs(extractable);
        }

        String usageList = usages != null ? String.join(",", Stream.of(usages).map(org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage::name).toArray(String[]::new)) : "";
        logger.debug("CryptoUtil: generateRSAKeyPair with key usage {}", usageList);
        String usageMaskList = usagesMask != null ? String.join(",", Stream.of(usagesMask).map(org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage::name).toArray(String[]::new)) : "";
        logger.debug("CryptoUtil: generateRSAKeyPair with key usage mask {}", usageMaskList);
        keygen.setKeyPairUsages(usages, usagesMask);

        keygen.initialize(curveCode);

        KeyPair pair = keygen.genKeyPair();
        PrivateKey privateKey = (PrivateKey) pair.getPrivate();
        String hexKeyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
        logger.debug("CryptoUtil: - key ID: " + hexKeyID);

        return pair;
    }

    public static void setClientCiphers(String list) throws SocketException {
          setClientCiphers(null, list);
    }
    public static void setClientCiphers(SSLSocket soc, String list) throws SocketException {
        String method = "CryptoUtil.setClientCiphers:";
        if (soc == null)
            logger.debug(method + "begins");
        else
            logger.debug(method + "on soc begins");

        if (list == null) {
            logger.debug(method + "no cipher list in call; using default");
            // use default
            if (soc == null)
                setDefaultSSLCiphers();
            return;
        }

        logger.debug(method + "cipher list in call; processing...");
        String[] ciphers = list.split(",");
        if (ciphers.length == 0)
            return;

        if (soc == null)
            unsetSSLCiphers();
        else
            unsetSSLCiphers(soc);

        for (String cipher : ciphers) {
            try {
                if (soc == null)
                    setSSLCipher(cipher, true);
                else
                    setSSLCipher(soc, cipher, true);
            } catch (Exception e) {
                logger.debug(method + cipher + " failed to be set: " + e.toString());
            }
        }
        logger.debug(method + "ends");
    }

    public static void setSSLCiphers(String ciphers) throws SocketException {
        String method = "CryptoUtil.setSSLCiphers:";
        logger.debug(method + "begins");
        if (ciphers == null) return;

        StringTokenizer st = new StringTokenizer(ciphers);

        while (st.hasMoreTokens()) {
            String cipher = st.nextToken();
            boolean enabled = true;

            if (cipher.startsWith("-")) {
                enabled = false;
                cipher = cipher.substring(1);
            }

            setSSLCipher(cipher, enabled);
        }
        logger.debug(method + "ends");
    }

    public static void setSSLCipher(SSLSocket soc, String name, boolean enabled) throws SocketException {
        logger.debug("CryptoUtil.setSSLCipher on soc: setting cipher:" + name);
        int cipherID;
        if (name.toLowerCase().startsWith("0x")) {
            cipherID = Integer.parseInt(name.substring(2), 16);

        } else {
            SSLCipher cipher = SSLCipher.valueOf(name);
            cipherID = cipher.getID();
        }

        soc.setCipherPreference(cipherID, enabled);
    }

    public static void setSSLCipher(String name, boolean enabled) throws SocketException {
        logger.debug("CryptoUtil.setSSLCipher: setting cipher:" + name);
        int cipherID;
        if (name.toLowerCase().startsWith("0x")) {
            cipherID = Integer.parseInt(name.substring(2), 16);

        } else {
            SSLCipher cipher = SSLCipher.valueOf(name);
            cipherID = cipher.getID();
        }

        SSLSocket.setCipherPreferenceDefault(cipherID, enabled);
    }

    public static void setDefaultSSLCiphers() throws SocketException {
        logger.debug("CryptoUtil.setDefaultSSLCiphers");
        int[] ciphers = SSLSocket.getImplementedCipherSuites();
        if (ciphers == null)
            return;

        for (int cipher : ciphers) {

            boolean enabled = SSLSocket.getCipherPreferenceDefault(cipher);
            //logger.debug("CryptoUtil: cipher '0x" +
            //    Integer.toHexString(ciphers[j]) + "'" + " enabled? " +
            //    enabled);

            // make sure SSLv2 ciphers are not enabled
            if ((cipher & 0xfff0) == 0xff00) {

                if (!enabled)
                    continue;

                //logger.debug("CryptoUtil: disabling SSLv2 NSS Cipher '0x" +
                //    Integer.toHexString(ciphers[j]) + "'");
                SSLSocket.setCipherPreferenceDefault(cipher, false);
                continue;
            }

            // unlike RSA ciphers, ECC ciphers are not enabled by default
            if (!enabled && clientECCipherList.contains(cipher)) {
                //logger.debug("CryptoUtil: enabling ECC NSS Cipher '0x" +
                //    Integer.toHexString(ciphers[j]) + "'");
                SSLSocket.setCipherPreferenceDefault(cipher, true);
            }
        }
    }

    /*
     * unset all implemented cipehrs; for enforcing strict list of ciphers
     */
    public static void unsetSSLCiphers() throws SocketException {
        logger.debug("CryptoUtil.unsetSSLCiphers");
        int[] cipherIDs = SSLSocket.getImplementedCipherSuites();
        if (cipherIDs == null)
            return;

        for (int cipherID : cipherIDs) {
            // logger.debug("CryptoUtil.setSSLCipher: unsetting cipher:" + cipherID);
            SSLSocket.setCipherPreferenceDefault(cipherID, false);
        }
    }
    public static void unsetSSLCiphers(SSLSocket soc) throws SocketException {
        logger.debug("CryptoUtil.unsetSSLCiphers on soc");
        int[] cipherIDs = SSLSocket.getImplementedCipherSuites();
        if (cipherIDs == null) return;

        for (int cipherID : cipherIDs) {
            // logger.debug("CryptoUtil.setSSLCipher: unsetting cipher on soc:" + cipherID);
            soc.setCipherPreference(cipherID, false);
        }
    }

    public static byte[] getModulus(PublicKey pubk) {
        RSAPublicKey rsaKey = (RSAPublicKey) pubk;

        return rsaKey.getModulus().toByteArray();
    }

    public static byte[] getPublicExponent(PublicKey pubk) {
        RSAPublicKey rsaKey = (RSAPublicKey) pubk;

        return rsaKey.getPublicExponent().toByteArray();
    }

    public static String base64Encode(byte[] bytes) throws IOException {
        // All this streaming is lame, but Base64OutputStream needs a
        // PrintStream
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (Base64OutputStream b64 = new Base64OutputStream(
                new PrintStream(new FilterOutputStream(output)))) {

            b64.write(bytes);
            b64.flush();

            // This is internationally safe because Base64 chars are
            // contained within 8859_1
            return output.toString("8859_1");
        }
    }

    public static byte[] base64Decode(String s) {
        return Utils.base64decode(s);
    }

    /*
     * formats a cert request
     */
    public static String reqFormat(String content) {
        StringBuffer result = new StringBuffer();
        result.append(Cert.REQUEST_HEADER + "\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT) + "\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result.append(content + "\n" + Cert.REQUEST_FOOTER);
        } else {
            result.append(Cert.REQUEST_FOOTER);
        }

        return result.toString();
    }

    /*
     * formats a cert
     */
    public static String certFormat(String content) {
        if (content == null || content.length() == 0) {
            return "";
        }
        StringBuffer result = new StringBuffer();
        result.append(Cert.HEADER + "\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT) + "\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result.append(content + "\n" + Cert.FOOTER);
        } else {
            result.append(Cert.FOOTER);
        }

        return result.toString();
    }

    /**
     * strips out the begin and end certificate brackets
     *
     * @param s the string potentially bracketed with
     *            "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
     * @return string without the brackets
     */
    public static String stripCertBrackets(String s) {
        if (s == null) {
            return s;
        }

        if (s.startsWith(Cert.HEADER) && s.endsWith(Cert.FOOTER)) {
            return (s.substring(27, (s.length() - 25)));
        }

        // To support Thawte's header and footer
        if ((s.startsWith("-----BEGIN PKCS #7 SIGNED DATA-----"))
                && (s.endsWith("-----END PKCS #7 SIGNED DATA-----"))) {
            return (s.substring(35, (s.length() - 33)));
        }

        return s;
    }

    public static String normalizeCertAndReq(String s) {
        if (s == null) {
            return s;
        }
        // grammar defined at https://tools.ietf.org/html/rfc7468#section-3
        s = s.replaceAll("-----(BEGIN|END) [\\p{Print}&&[^- ]]([- ]?[\\p{Print}&&[^- ]])*-----", "");

        return Utils.normalizeString(s);
    }

    public static String normalizeCertStr(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            } else if (s.charAt(i) == ' ') {
                continue;
            }
            val.append(s.charAt(i));
        }
        return val.toString();
    }

    public static X509Certificate[] importPKCS7(
            PKCS7 pkcs7,
            String nickname,
            String trustFlags) throws Exception {

        CryptoManager manager = CryptoManager.getInstance();

        java.security.cert.X509Certificate[] pkcs7Certs = pkcs7.getCertificates();
        X509Certificate[] nssCerts = new X509Certificate[pkcs7Certs.length];

        // sort certs from root to leaf
        pkcs7Certs = Cert.sortCertificateChain(pkcs7Certs);

        // import certs one by one
        for (int i = 0; i < pkcs7Certs.length; i++) {

            java.security.cert.X509Certificate pkcs7Cert = pkcs7Certs[i];
            byte[] bytes = pkcs7Cert.getEncoded();

            if (i == 0) {
                // root CA cert
                nssCerts[i] = manager.importCACertPackage(bytes);

            } else if (i < pkcs7Certs.length - 1 || nickname == null) {
                // intermediate CA cert
                nssCerts[i] = manager.importCACertPackage(bytes);

            } else {
                // leaf cert
                nssCerts[i] = manager.importCertPackage(bytes, nickname);
            }
        }

        X509Certificate rootCACert = nssCerts[0];
        trustCACert(rootCACert);

        if (trustFlags != null) {
            X509Certificate leafCert = nssCerts[nssCerts.length - 1];
            setTrustFlags(leafCert, trustFlags);
        }

        return nssCerts;
    }

    public static X509Certificate[] importPKCS7(PKCS7 pkcs7) throws Exception {
        return importPKCS7(pkcs7, null, null);
    }

    public static void importCertificateChain(byte[] bytes) throws Exception {

        try {
            // try PKCS7 first
            PKCS7 pkcs7 = new PKCS7(bytes);
            importPKCS7(pkcs7);

        } catch (ParsingException e) {
            // not PKCS7

            CryptoManager manager = CryptoManager.getInstance();

            X509Certificate leafCert = manager.importCACertPackage(bytes);
            X509Certificate[] certs = manager.buildCertificateChain(leafCert);

            X509Certificate rootCert = certs[certs.length - 1];
            trustCACert(rootCert);
        }
    }

    public static X509Key createX509Key(PublicKey publicKey) throws InvalidKeyException {

        if (publicKey instanceof RSAPublicKey) {

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            return new org.mozilla.jss.netscape.security.provider.RSAPublicKey(
                    new BigInt(rsaPublicKey.getModulus()),
                    new BigInt(rsaPublicKey.getPublicExponent()));

        } else if (publicKey instanceof ECPublicKey) {

            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            try {
                DerValue derValue = new DerValue(ecPublicKey.getEncoded());
                return X509Key.parse(derValue);
            } catch (IOException e) {
                throw new InvalidKeyException(e);
            }

        } else if (publicKey instanceof DSAPublicKey) {

            DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
            DSAParams params = dsaPublicKey.getParams();
            return new org.mozilla.jss.netscape.security.provider.DSAPublicKey(
                    dsaPublicKey.getY(),
                    params.getP(),
                    params.getQ(),
                    params.getG());

        } else {
            String message = "Unsupported public key: " + publicKey.getClass().getName();
            logger.error(message);
            throw new InvalidKeyException(message);
        }
    }

    /**
     * Creates a Certificate template.
     */
    public static X509CertInfo createX509CertInfo(
            X509Key x509key,
            BigInteger serialno,
            CertificateIssuerName issuerName,
            X500Name subjectName,
            Date notBefore,
            Date notAfter,
            String alg,
            CertificateExtensions extensions)
            throws IOException,
            CertificateException,
            NoSuchAlgorithmException {

        X509CertInfo info = new X509CertInfo();

        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialno));

        if (issuerName != null) {
            info.set(X509CertInfo.ISSUER, issuerName);
        }

        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subjectName));
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(alg)));
        info.set(X509CertInfo.KEY, new CertificateX509Key(x509key));
        info.set(X509CertInfo.EXTENSIONS, extensions);

        return info;
    }

    public static X509CertImpl signECCCert(
            java.security.PrivateKey privateKey,
            X509CertInfo certInfo)
            throws Exception {
        // set default; use the other call with "alg" to specify algorithm
        String alg = "SHA256withEC";
        return signCert(privateKey, certInfo, alg);
    }

    /**
     * Signs certificate.
     */
    public static X509CertImpl signCert(
            java.security.PrivateKey privateKey,
            X509CertInfo certInfo,
            String alg)
            throws Exception {
        SignatureAlgorithm signingAlgorithm = Cert.mapAlgorithmToJss(alg);
        return signCert(privateKey, certInfo, signingAlgorithm);
    }

    public static X509CertImpl signCert(
            java.security.PrivateKey privateKey,
            X509CertInfo certInfo,
            SignatureAlgorithm signingAlgorithm)
            throws Exception {

        logger.debug("CryptoUtil: Signing certificate");
        logger.debug("CryptoUtil: - signing algorithm: " + signingAlgorithm);

        String algName = mapSignatureAlgorithmToInternalName(signingAlgorithm);
        logger.debug("CryptoUtil: - algorithm name: " + algName);

        AlgorithmId aid = AlgorithmId.get(algName);
        logger.debug("CryptoUtil: - algorithm ID: " + aid);

        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(aid));

        PrivateKey priKey = (PrivateKey) privateKey;
        CryptoToken token = priKey.getOwningToken();

        Signature signer = token.getSignatureContext(signingAlgorithm);
        signer.initSign(priKey);

        try (DerOutputStream tmp = new DerOutputStream();
                DerOutputStream out = new DerOutputStream()) {

            certInfo.encode(tmp);
            signer.update(tmp.toByteArray());
            byte[] signed = signer.sign();

            aid.encode(tmp);
            tmp.putBitString(signed);

            out.write(DerValue.tag_Sequence, tmp);
            return new X509CertImpl(out.toByteArray());
        }
    }

    /**
     * Creates a PKCS #10 request.
     */
    public static PKCS10 createPKCS10Request(
            String subjectName,
            boolean encodeSubj,
            KeyPair keyPair,
            String alg,
            Extensions exts) throws Exception {

        logger.debug("CryptoUtil: Creating PKCS #10 request");
        X509Key key = createX509Key(keyPair.getPublic());

        logger.debug("CryptoUtil: - algorithm: " + alg);
        java.security.Signature sig = java.security.Signature.getInstance(alg, "Mozilla-JSS");
        sig.initSign(keyPair.getPrivate());

        logger.debug("CryptoUtil: - subject: " + subjectName);

        X500Name name = null;
        if (!encodeSubj)
            name = new X500Name(subjectName);
        else {
            Name n = createName(subjectName, encodeSubj);
            ByteArrayOutputStream subjectEncStream = new ByteArrayOutputStream();
            n.encode(subjectEncStream);
            byte[] b = subjectEncStream.toByteArray();
            name = new X500Name(b);
        }
        X500Signer signer = new X500Signer(sig, name);

        logger.debug("CryptoUtil: - attributes:");
        PKCS10Attributes attrs = new PKCS10Attributes();
        if (exts != null && !exts.isEmpty()) {
            PKCS10Attribute attr = new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID, exts);
            String attrName = attr.getAttributeValue().getName();
            logger.debug("CryptoUtil:   - " + attrName);
            attrs.setAttribute(attrName, attr);
        }

        PKCS10 pkcs10 = new PKCS10(key, attrs);
        pkcs10.encodeAndSign(signer);

        return pkcs10;
    }

    public static Signature createSigner(
            CryptoToken token,
            SignatureAlgorithm signatureAlgorithm,
            KeyPair keyPair) throws Exception {

        Signature signer = token.getSignatureContext(signatureAlgorithm);
        signer.initSign((org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate());

        return signer;
    }

    public static boolean isEncoded(String elementValue) {

        if (elementValue == null) return false;

        return elementValue.startsWith("UTF8String:")
                || elementValue.startsWith("PrintableString:")
                || elementValue.startsWith("BMPString:")
                || elementValue.startsWith("TeletexString:")
                || elementValue.startsWith("UniversalString:");
    }

    public static AVA createAVA(OBJECT_IDENTIFIER oid, int n, String elementValue) throws Exception {

        String encodingType = n > 0 ? elementValue.substring(0, n) : null;
        String nameValue = n > 0 ? elementValue.substring(n+1) : null;

        if (encodingType != null && encodingType.length() > 0
                && nameValue != null && nameValue.length() > 0) {

            if (encodingType.equals("UTF8String")) {
                return new AVA(oid, new UTF8String(nameValue));

            } else if (encodingType.equals("PrintableString")) {
                return new AVA(oid, new PrintableString(nameValue));

            } else if (encodingType.equals("BMPString")) {
                return new AVA(oid, new BMPString(nameValue));

            } else if (encodingType.equals("TeletexString")) {
                return new AVA(oid, new TeletexString(nameValue));

            } else if (encodingType.equals("UniversalString")) {
                return new AVA(oid, new UniversalString(nameValue));

            } else {
                throw new Exception("Unsupported encoding: " + encodingType);
            }
        }

        return null;
    }

    public static Name createName(String dn, boolean encodingEnabled) throws Exception {

        X500Name x500Name = new X500Name(dn);
        Name jssName = new Name();

        for (org.mozilla.jss.netscape.security.x509.RDN rdn : x500Name.getNames()) {

            String rdnStr = rdn.toString();
            logger.info("CryptoUtil: RDN: " + rdnStr);

            String[] split = rdnStr.split("=");
            if (split.length != 2) {
                continue;
            }

            String attribute = split[0];
            String value = split[1];

            int n = value.indexOf(':');

            if (attribute.equalsIgnoreCase("UID")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"), n, value));
                } else {
                    jssName.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"), new PrintableString(value)));
                }

            } else if (attribute.equalsIgnoreCase("C")) {
                jssName.addCountryName(value);

            } else if (attribute.equalsIgnoreCase("CN")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.commonName, n, value));
                } else {
                    jssName.addCommonName(value);
                }

            } else if (attribute.equalsIgnoreCase("L")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.localityName, n, value));
                } else {
                    jssName.addLocalityName(value);
                }

            } else if (attribute.equalsIgnoreCase("O")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.organizationName, n, value));
                } else {
                    jssName.addOrganizationName(value);
                }

            } else if (attribute.equalsIgnoreCase("ST")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.stateOrProvinceName, n, value));
                } else {
                    jssName.addStateOrProvinceName(value);
                }

            } else if (attribute.equalsIgnoreCase("OU")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.organizationalUnitName, n, value));
                } else {
                    jssName.addOrganizationalUnitName(value);
                }

            } else {
                throw new Exception("Unsupported attribute: " + attribute);
            }
        }

        return jssName;
    }
    public static KeyIdentifier createKeyIdentifier(KeyPair keypair) throws InvalidKeyException {
        String method = "CryptoUtil: createKeyIdentifier: ";
        logger.debug(method + "begins");

        X509Key subjectKeyInfo = createX509Key(keypair.getPublic());

        byte[] hash = generateKeyIdentifier(subjectKeyInfo.getKey());

        if (hash == null) {
            logger.debug(method +
                    "generateKeyIdentifier returns null");
            return null;
        }
        return new KeyIdentifier(hash);
    }

    public static byte[] generateKeyIdentifier(byte[] rawKey) {
        return generateKeyIdentifier(rawKey, null);
    }

    public static byte[] generateKeyIdentifier(byte[] rawKey, String alg) {
        String method = "CryptoUtil: generateKeyIdentifier: ";
        String msg = "";
        if (alg == null) {
            alg = "SHA-1";
        }
        try {
            MessageDigest md = MessageDigest.getInstance(alg);

            md.update(rawKey);
            return md.digest();
        } catch (Exception e) {
            msg = method + e;
            logger.warn(msg, e);
        }
        return null;
    }

    public static String getSKIString(X509CertImpl cert) throws IOException {

        SubjectKeyIdentifierExtension ext = (SubjectKeyIdentifierExtension) cert
                .getExtension(PKIXExtensions.SubjectKey_Id.toString());

        byte[] ski;

        if (ext == null) {

            // SKI not available, generate a new one
            ski = CryptoUtil.generateKeyIdentifier(cert.getPublicKey().getEncoded());

        } else {

            // use existing SKI
            KeyIdentifier keyId = (KeyIdentifier) ext.get(SubjectKeyIdentifierExtension.KEY_ID);
            ski = keyId.getIdentifier();
        }

        // format SKI: xx:xx:xx:...
        org.mozilla.jss.netscape.security.util.PrettyPrintFormat pp = new org.mozilla.jss.netscape.security.util.PrettyPrintFormat(
                ":", 20);
        return pp.toHexString(ski).trim();
    }

    /*
     * get extension from  PKCS10 request
     */
    public static org.mozilla.jss.netscape.security.x509.Extension getExtensionFromPKCS10(PKCS10 pkcs10,
            String extnName)
            throws IOException, CertificateException {
        Extension extn = null;

        String method = "CryptoUtiil: getExtensionFromPKCS10: ";
        logger.debug(method + "begins");

        PKCS10Attributes attributeSet = pkcs10.getAttributes();
        if (attributeSet == null) {
            logger.debug(method + "attributeSet not found");
            return null;
        }
        PKCS10Attribute attr = attributeSet.getAttribute("extensions");
        if (attr == null) {
            logger.debug(method + "extensions attribute not found");
            return null;
        }
        logger.debug(method + attr);

        CertAttrSet cas = attr.getAttributeValue();
        if (cas == null) {
            logger.debug(method + "CertAttrSet not found in PKCS10Attribute");
            return null;
        }

        Enumeration<String> en = cas.getAttributeNames();
        while (en.hasMoreElements()) {
            String name = en.nextElement();
            logger.debug(method + " checking extension in request:" + name);
            if (name.equals(extnName)) {
                logger.debug(method + "extension matches");
                extn = (Extension) cas.get(name);
            }
        }

        logger.debug(method + "ends");
        return extn;
    }

    public static void unTrustCert(PK11Cert cert) {
        // remove TRUSTED_CA
        int flag = cert.getSSLTrust();

        flag ^= PK11Cert.VALID_CA;
        cert.setSSLTrust(flag);
    }

    /**
     * Trusts a certificate by nickname.
     */
    public static void trustCertByNickname(String nickname)
            throws NotInitializedException,
            TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate[] certs = cm.findCertsByNickname(nickname);

        if (certs == null) {
            return;
        }
        for (int i = 0; i < certs.length; i++) {
            trustCert((PK11Cert) certs[i]);
        }
    }

    /**
     * Trusts a certificate.
     */
    public static void trustCert(PK11Cert cert) {
        int flag = PK11Cert.VALID_CA | PK11Cert.TRUSTED_CA
                | PK11Cert.USER
                | PK11Cert.TRUSTED_CLIENT_CA;

        cert.setSSLTrust(flag);
        cert.setObjectSigningTrust(flag);
        cert.setEmailTrust(flag);
    }

    public static void setTrustFlags(X509Certificate cert, String trustFlags) throws Exception {

        String[] flags = trustFlags.split(",", -1); // don't remove empty string
        if (flags.length < 3)
            throw new Exception("Invalid trust flags: " + trustFlags);

        PK11Cert internalCert = (PK11Cert) cert;
        internalCert.setSSLTrust(PK11Cert.decodeTrustFlags(flags[0]));
        internalCert.setEmailTrust(PK11Cert.decodeTrustFlags(flags[1]));
        internalCert.setObjectSigningTrust(PK11Cert.decodeTrustFlags(flags[2]));
    }

    public static void trustCACert(X509Certificate cert) {

        // set trust flags to CT,C,C
        PK11Cert ic = (PK11Cert) cert;

        ic.setSSLTrust(PK11Cert.TRUSTED_CA
                | PK11Cert.TRUSTED_CLIENT_CA
                | PK11Cert.VALID_CA);

        ic.setEmailTrust(PK11Cert.TRUSTED_CA
                | PK11Cert.VALID_CA);

        ic.setObjectSigningTrust(PK11Cert.TRUSTED_CA
                | PK11Cert.VALID_CA);
    }

    public static void trustAuditSigningCert(X509Certificate cert) {

        // set trust flags to u,u,Pu
        PK11Cert ic = (PK11Cert) cert;

        ic.setSSLTrust(PK11Cert.USER);

        ic.setEmailTrust(PK11Cert.USER);

        ic.setObjectSigningTrust(PK11Cert.USER
                | PK11Cert.VALID_PEER
                | PK11Cert.TRUSTED_PEER);
    }

    /**
     * To certificate server point of view, SSL trust is
     * what we referring.
     */
    public static boolean isCertTrusted(PK11Cert cert) {
        return isTrust(cert.getSSLTrust())
                && isTrust(cert.getObjectSigningTrust())
                && isTrust(cert.getEmailTrust());
    }

    public static boolean isTrust(int flag) {
        return ((flag & PK11Cert.VALID_CA) > 0)
                && ((flag & PK11Cert.TRUSTED_CA) > 0)
                && ((flag & PK11Cert.USER) > 0)
                && ((flag & PK11Cert.TRUSTED_CLIENT_CA) > 0);
    }

    public static SymmetricKey generateKey(
            CryptoToken token,
            KeyGenAlgorithm alg,
            int keySize,
            SymmetricKey.Usage[] usages,
            boolean temporary) throws Exception {

        return generateKey(token, alg, keySize, usages, temporary, null);
    }

    public static SymmetricKey generateKey(
            CryptoToken token,
            KeyGenAlgorithm alg,
            int keySize,
            SymmetricKey.Usage[] usages,
            boolean temporary,
            Boolean sensitive) throws Exception {

        KeyGenerator kg = token.getKeyGenerator(alg);

        if (usages != null) {
            kg.setKeyUsages(usages);
        }

        if (sensitive != null) {
            kg.sensitiveKeys(sensitive);
        }

        kg.temporaryKeys(temporary);

        if (alg == KeyGenAlgorithm.AES || alg == KeyGenAlgorithm.RC4
                || alg == KeyGenAlgorithm.RC2) {
            kg.initialize(keySize);
        }

        return kg.generate();
    }

    /**
     * Compares 2 byte arrays to see if they are the same.
     */
    public static boolean compare(byte[] src, byte[] dest) {
        if (src != null && dest != null) {
            if (src.length == dest.length) {
                boolean matched = true;

                for (int i = 0; i < src.length; i++) {
                    if (src[i] != dest[i]) {
                        matched = false;
                    }
                }
                if (matched) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Converts any length byte array into a signed, variable-length
     * hexadecimal number.
     */
    public static String byte2string(byte[] id) {
        return new BigInteger(id).toString(16);
    }

    /**
     * Converts a signed, variable-length hexadecimal number into a byte
     * array, which may not be identical to the original byte array.
     */
    public static byte[] string2byte(String id) {
        return new BigInteger(id, 16).toByteArray();
    }

    /**
     * Converts NSS key ID from a 20 byte array into a signed, variable-length
     * hexadecimal number (to maintain compatibility with byte2string()).
     */
    public static String encodeKeyID(byte[] keyID) {

        if (keyID.length != KEY_ID_LENGTH) {
            String hexKeyID = "0x" + Utils.HexEncode(keyID);
            throw new IllegalArgumentException("Unable to encode Key ID: " + hexKeyID);
        }

        return new BigInteger(keyID).toString(16);
    }

    /**
     * Converts NSS key ID from a signed, variable-length hexadecimal number
     * into a 20 byte array, which will be identical to the original byte array.
     *
     * @throws DecoderException
     */
    public static byte[] decodeKeyID(String id) throws DecoderException {

        if (id.startsWith("0x")) {
            id = id.substring(2);
            if (id.length() % 2 == 1) id = "0" + id;
            return Hex.decodeHex(id);
        }

        BigInteger value = new BigInteger(id, 16);
        byte[] array = value.toByteArray();

        if (array.length > KEY_ID_LENGTH) {
            throw new IllegalArgumentException(
                    "Unable to decode Key ID: " + id);
        }

        if (array.length < KEY_ID_LENGTH) {

            // extend the array with most significant bit
            byte[] tmp = array;
            array = new byte[KEY_ID_LENGTH];

            // calculate the extension
            int p = KEY_ID_LENGTH - tmp.length;

            // create filler byte based op the most significant bit
            byte b = (byte) (value.signum() >= 0 ? 0x00 : 0xff);

            // fill the extension with the filler byte
            Arrays.fill(array, 0, p, b);

            // copy the original array
            System.arraycopy(tmp, 0, array, p, tmp.length);
        }

        return array;
    }

    /**
     * Converts string containing pairs of characters in the range of '0'
     * to '9', 'a' to 'f' to an array of bytes such that each pair of
     * characters in the string represents an individual byte
     */
    public static byte[] hexString2Bytes(String string) {
        if (string == null)
            return null;
        int stringLength = string.length();
        if ((stringLength == 0) || ((stringLength % 2) != 0))
            return null;
        byte[] bytes = new byte[(stringLength / 2)];
        for (int i = 0, b = 0; i < stringLength; i += 2, ++b) {
            String nextByte = string.substring(i, (i + 2));
            bytes[b] = (byte) Integer.parseInt(nextByte, 0x10);
        }
        return bytes;
    }

    public static char[] bytesToChars(byte[] bytes) {
        if (bytes == null)
            return null;

        Charset charset = Charset.forName("UTF-8");
        CharBuffer charBuffer = charset.decode(ByteBuffer.wrap(bytes));
        char[] result = Arrays.copyOf(charBuffer.array(), charBuffer.limit());

        //Clear up the CharBuffer we just created
        if (charBuffer.hasArray()) {
            char[] contentsToBeErased = charBuffer.array();
            CryptoUtil.obscureChars(contentsToBeErased);
        }
        return result;
    }

    public static byte[] charsToBytes(char[] chars) {
        if (chars == null)
            return null;

        Charset charset = Charset.forName("UTF-8");
        ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(chars));
        byte[] result = Arrays.copyOf(byteBuffer.array(), byteBuffer.limit());

        if (byteBuffer.hasArray()) {
            byte[] contentsToBeErased = byteBuffer.array();
            CryptoUtil.obscureBytes(contentsToBeErased, "random");
        }
        return result;
    }

    /**
     * Create a jss Password object from a provided byte array.
     */
    public static Password createPasswordFromBytes(byte[] bytes) {

        if (bytes == null)
            return null;

        char[] pwdChars = bytesToChars(bytes);
        Password password = new Password(pwdChars);
        obscureChars(pwdChars);

        return password;
    }

    /**
     * Finds private key by key ID in all tokens.
     */
    public static PrivateKey findPrivateKey(byte[] id) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        Enumeration<CryptoToken> enums = cm.getAllTokens();

        while (enums.hasMoreElements()) {
            CryptoToken token = enums.nextElement();
            PrivateKey privateKey = findPrivateKey(token, id);

            if (privateKey != null) {
                return privateKey;
            }
        }

        return null;
    }

    /**
     * Finds private key by key ID in specified token.
     */
    public static PrivateKey findPrivateKey(CryptoToken token, byte[] id) throws Exception {

        CryptoStore store = token.getCryptoStore();
        PrivateKey[] privateKeys = store.getPrivateKeys();

        if (privateKeys == null) {
            return null;
        }

        for (PrivateKey privateKey : privateKeys) {
            if (compare(privateKey.getUniqueID(), id)) {
                return privateKey;
            }
        }

        return null;
    }

    /**
     * Finds private key by cert nickname.
     */
    public static PrivateKey findPrivateKey(String nickname) throws Exception {
        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(nickname);
            return cm.findPrivKeyByCert(cert);

        } catch (ObjectNotFoundException e) {
            return null;
        }
    }

    /**
     * Retrieves all user certificates from all tokens.
     */
    public static X509CertImpl[] getAllUserCerts()
            throws NotInitializedException,
            TokenException {
        Vector<X509CertImpl> certs = new Vector<>();
        CryptoManager cm = CryptoManager.getInstance();
        Enumeration<CryptoToken> enums = cm.getAllTokens();

        while (enums.hasMoreElements()) {
            CryptoToken token = enums.nextElement();

            CryptoStore store = token.getCryptoStore();
            org.mozilla.jss.crypto.X509Certificate[] list = store.getCertificates();

            for (int i = 0; i < list.length; i++) {
                try {
                    @SuppressWarnings("unused")
                    PrivateKey key = cm.findPrivKeyByCert(list[i]); // check for errors
                    X509CertImpl impl = null;

                    try {
                        impl = new X509CertImpl(list[i].getEncoded());
                    } catch (CertificateException e) {
                        continue;
                    }
                    certs.addElement(impl);
                } catch (TokenException | ObjectNotFoundException e) {
                    // Swallow exception - why? TODO
                }
            }
        }
        if (certs.isEmpty()) {
            return null;
        }
        X509CertImpl[] c = new X509CertImpl[certs.size()];
        certs.copyInto(c);
        return c;
    }

    /**
     * Deletes a private key.
     */
    public static void deletePrivateKey(PrivateKey prikey) throws TokenException {

        try {
            CryptoToken token = prikey.getOwningToken();
            CryptoStore store = token.getCryptoStore();

            store.deletePrivateKey(prikey);
        } catch (NoSuchItemOnTokenException e) {
        }
    }

    /**
     * Deletes all certificates by a nickname.
     */
    public static void deleteCertificates(String nickname)
            throws TokenException, ObjectNotFoundException,
            NoSuchItemOnTokenException, NotInitializedException {

        deleteCertificates(nickname, true);
    }

    public static void deleteCertificates(String nickname, boolean removeKey)
            throws TokenException, ObjectNotFoundException,
            NoSuchItemOnTokenException, NotInitializedException {

        CryptoManager manager = CryptoManager.getInstance();

        logger.info("Finding cert " + nickname);
        X509Certificate[] certs = manager.findCertsByNickname(nickname);

        if (certs == null || certs.length == 0) {
            throw new ObjectNotFoundException("Certificate not found: " + nickname);
        }

        for (X509Certificate cert : certs) {

            CryptoToken token;
            if (cert instanceof PK11Cert tokenCert) {
                token = tokenCert.getOwningToken();

            } else {
                token = manager.getInternalKeyStorageToken();
            }

            CryptoStore store = token.getCryptoStore();

            if (removeKey) {
                logger.info("Removing cert " + nickname + " and the key");
                store.deleteCert(cert);

            } else {
                logger.info("Removing cert " + nickname);
                store.deleteCertOnly(cert);
            }
        }
    }

    /**
     * Deletes user certificates by a nickname.
     */
    public static void deleteUserCertificates(String nickname)
            throws NotInitializedException, TokenException {

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate[] certs = cm.findCertsByNickname(nickname);

        if (certs == null) {
            return;
        }

        for (X509Certificate cert : certs) {
            try {
                org.mozilla.jss.crypto.PrivateKey prikey = cm.findPrivKeyByCert(
                        cert);
                CryptoToken token = prikey.getOwningToken();
                CryptoStore store = token.getCryptoStore();

                store.deleteCert(cert);
            } catch (NoSuchItemOnTokenException | ObjectNotFoundException e) {
            }
        }
    }

    /**
     * Imports a PKCS#7 certificate chain that includes the user
     * certificate, and trusts the certificate.
     */
    public static X509Certificate importUserCertificateChain(String c,
            String nickname)
            throws NotInitializedException,
            NicknameConflictException,
            UserCertConflictException,
            NoSuchItemOnTokenException,
            TokenException,
            CertificateEncodingException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate cert = cm.importCertPackage(c.getBytes(), nickname);

        trustCertByNickname(nickname);
        return cert;
    }

    /**
     * Imports a user certificate.
     */
    public static X509Certificate importUserCertificate(byte[] bytes, String nickname)
            throws NotInitializedException,
            CertificateEncodingException,
            NoSuchItemOnTokenException,
            TokenException,
            NicknameConflictException,
            UserCertConflictException {

        CryptoManager cm = CryptoManager.getInstance();
        return cm.importUserCACertPackage(bytes, nickname);
    }

    public static java.security.cert.X509Certificate[] getX509CertificateFromPKCS7(byte[] b) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        CertificateChain certchain = new CertificateChain();

        certchain.decode(bis);
        return certchain.getChain();
    }

    /**
     * Generates a nonce_iv for padding.
     *
     * @throws GeneralSecurityException
     */
    public static byte[] getNonceData(int size) throws GeneralSecurityException {
        byte[] iv = new byte[size];

        SecureRandom rnd = CryptoUtil.getRandomNumberGenerator();
        rnd.nextBytes(iv);

        return iv;
    }

    public static SecureRandom getRandomNumberGenerator() throws GeneralSecurityException {
        return SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
    }

    public static void obscureChars(char[] memory) {
        if (memory == null || memory.length == 0) {
            //in case we want to log
            return;
        }
        Arrays.fill(memory, (char) 0);
    }

    public static void obscureBytes(byte[] memory, String method) {
        if (memory == null || memory.length == 0) {
            //in case we want to log
            return;
        }

        SecureRandom rnd;
        try {
            rnd = getRandomNumberGenerator();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        if ("zeroes".equals(method)) {
            Arrays.fill(memory, (byte) 0);
        } else {
            rnd.nextBytes(memory);
        }
    }

    public static byte[] unwrapUsingPassphrase(byte[] wrappedRecoveredKey, String recoveryPassphrase)
            throws IOException, InvalidBERException, InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, NotInitializedException, TokenException,
            IllegalBlockSizeException, BadPaddingException {
        EncryptedContentInfo cInfo = null;

        //We have to do this to get the decoding to work.
        // TODO (alee) - this needs to work with AES keys.  It does not appear to be used though in the current KeyClient
        // We may end up simply removing this.
        @SuppressWarnings("unused")
        PBEAlgorithm pbeAlg = PBEAlgorithm.PBE_SHA1_DES3_CBC;

        Password pass = new Password(recoveryPassphrase.toCharArray());
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(wrappedRecoveredKey);){
            PasswordConverter passConverter = new PasswordConverter();

            cInfo = (EncryptedContentInfo) new EncryptedContentInfo.Template().decode(inStream);

            return cInfo.decrypt(pass, passConverter);

        } finally {
            pass.clear();
        }
    }

    public static byte[] encryptSecret(
            CryptoToken token,
            byte[] secret,
            IVParameterSpec iv,
            SymmetricKey key,
            EncryptionAlgorithm algorithm)
            throws NoSuchAlgorithmException, TokenException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = token.getCipherContext(algorithm);
        cipher.initEncrypt(key, iv);
        return cipher.doFinal(secret);
    }

    public static byte[] wrapSymmetricKey(
            CryptoToken token,
            PublicKey wrappingKey,
            SymmetricKey sk) throws Exception {
        return wrapUsingPublicKey(token, wrappingKey, sk, KeyWrapAlgorithm.RSA);
    }

    /* Used to create PKIArchiveOptions for wrapped private key */
    public static PKIArchiveOptions createPKIArchiveOptions(
            CryptoToken token,
            PublicKey wrappingKey,
            PrivateKey data,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {
        return createPKIArchiveOptionsInternal(
                token, wrappingKey, null, data, null, params, aid);
    }

    public static byte[] createEncodedPKIArchiveOptions(
            CryptoToken token,
            PublicKey wrappingKey,
            PrivateKey data,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {
        PKIArchiveOptions opts = createPKIArchiveOptionsInternal(
                token, wrappingKey, null, data, null, params, aid);
        return encodePKIArchiveOptions(opts);
    }

    public static byte[] createEncodedPKIArchiveOptions(
            CryptoToken token,
            PublicKey wrappingKey,
            SymmetricKey data,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {
        PKIArchiveOptions opts = createPKIArchiveOptionsInternal(
                token, wrappingKey, null, null, data, params, aid);
        return encodePKIArchiveOptions(opts);
    }

    /* Used to create PKIArchiveOptions for wrapped passphrase */
    public static PKIArchiveOptions createPKIArchiveOptions(
            CryptoToken token,
            PublicKey wrappingKey,
            char[] data,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {
        return createPKIArchiveOptionsInternal(
                token, wrappingKey, data, null, null, params, aid);
    }

    public static byte[] createEncodedPKIArchiveOptions(
            CryptoToken token,
            PublicKey wrappingKey,
            char[] data,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {
        PKIArchiveOptions opts = createPKIArchiveOptionsInternal(
                token, wrappingKey, data, null, null, params, aid);
        return encodePKIArchiveOptions(opts);
    }

    private static PKIArchiveOptions createPKIArchiveOptionsInternal(
            CryptoToken token,
            PublicKey wrappingKey,
            char[] passphraseData,
            PrivateKey privKeyData,
            SymmetricKey symKeyData,
            WrappingParams params,
            AlgorithmIdentifier aid) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        SymmetricKey sessionKey = CryptoUtil.generateKey(
                token,
                params.getSkKeyGenAlgorithm(),
                params.getSkLength(),
                sess_key_usages,
                false, cm.FIPSEnabled() /* sensitive */);
        byte[] key_data;

        if (passphraseData != null) {

            byte[] secret = CryptoUtil.charsToBytes(passphraseData);
            key_data = encryptSecret(
                    token,
                    secret,
                    params.getPayloadEncryptionIV(),
                    sessionKey,
                    params.getPayloadEncryptionAlgorithm());

        } else if (privKeyData != null) {

            key_data = wrapUsingSymmetricKey(
                    token,
                    sessionKey,
                    privKeyData,
                    params.getPayloadWrappingIV(),
                    params.getPayloadWrapAlgorithm());

        } else if (symKeyData != null) {

            key_data = wrapUsingSymmetricKey(
                    token,
                    sessionKey,
                    symKeyData,
                    params.getPayloadWrappingIV(),
                    params.getPayloadWrapAlgorithm());

        } else {
            throw new IOException("No data to package in PKIArchiveOptions!");
        }

        byte[] session_data = wrapUsingPublicKey(
                token,
                wrappingKey,
                sessionKey,
                params.getSkWrapAlgorithm());

        return createPKIArchiveOptions(session_data, key_data, aid);
    }

    public static PKIArchiveOptions createPKIArchiveOptions(
            byte[] session_data, byte[] key_data, AlgorithmIdentifier aid) {
        // create PKIArchiveOptions structure
        EncryptedValue encValue = new EncryptedValue(
                null,
                aid,
                new BIT_STRING(session_data, 0),
                null,
                null,
                new BIT_STRING(key_data, 0));
        EncryptedKey key = new EncryptedKey(encValue);
        return new PKIArchiveOptions(key);
    }

    public static byte[] encodePKIArchiveOptions(PKIArchiveOptions opts) throws Exception {
        byte[] encoded = null;

        //Let's make sure we can decode the encoded PKIArchiveOptions..
        ByteArrayOutputStream oStream = new ByteArrayOutputStream();

        opts.encode(oStream);

        encoded = oStream.toByteArray();
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);

        @SuppressWarnings("unused")
        PKIArchiveOptions options = (PKIArchiveOptions) (new PKIArchiveOptions.Template()).decode(inStream);

        return encoded;
    }

    public static PrivateKey importPKIArchiveOptions(
            CryptoToken token, PrivateKey unwrappingKey,
            PublicKey pubkey, byte[] data, boolean useOAEPKeyWrap)
            throws InvalidBERException, Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        PKIArchiveOptions options = (PKIArchiveOptions) (new PKIArchiveOptions.Template()).decode(in);
        EncryptedKey encKey = options.getEncryptedKey();
        EncryptedValue encVal = encKey.getEncryptedValue();
        AlgorithmIdentifier algId = encVal.getSymmAlg();
        BIT_STRING encSymKey = encVal.getEncSymmKey();
        BIT_STRING encPrivKey = encVal.getEncValue();

        OBJECT_IDENTIFIER oid = algId.getOID();

        ASN1Value v = algId.getParameters();
        v = ((ANY) v).decodeWith(new OCTET_STRING.Template());
        byte[] iv = ((OCTET_STRING) v).toByteArray();
        IVParameterSpec ivps = new IVParameterSpec(iv);

        KeyWrapAlgorithm wrapAlg = KeyWrapAlgorithm.RSA;

        if (useOAEPKeyWrap) {
            wrapAlg = KeyWrapAlgorithm.RSA_OAEP;
        }
        // des-ede3-cbc
        if (oid.equals(new OBJECT_IDENTIFIER("1.2.840.113549.3.7"))) {
            SymmetricKey sk = unwrap(
                    token, SymmetricKey.Type.DES3, 0, SymmetricKey.Usage.UNWRAP,
                    unwrappingKey, encSymKey.getBits(), wrapAlg);
            return unwrap(
                    token, pubkey, false, sk, encPrivKey.getBits(),
                    KeyWrapAlgorithm.DES3_CBC_PAD, ivps);

            // aes128-cbc
        } else if (oid.equals(new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.1.2"))) {
            SymmetricKey sk = unwrap(
                    token, SymmetricKey.Type.AES, 0, SymmetricKey.Usage.UNWRAP,
                    unwrappingKey, encSymKey.getBits(), wrapAlg);
            return unwrap(
                    token, pubkey, false, sk, encPrivKey.getBits(),
                    KeyWrapAlgorithm.AES_CBC_PAD, ivps);

            // unsupported algorithm
        } else {
            throw new IOException(
                    "PKIArchiveOptions symmetric algorithm " + oid.toString() + " not supported");
        }

    }

    public static boolean sharedSecretExists(String nickname) throws NotInitializedException, TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyManager km = new KeyManager(token);
        return km.uniqueNamedKeyExists(nickname);
    }

    public static void createSharedSecret(String nickname) throws NotInitializedException, TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyManager km = new KeyManager(token);
        km.generateUniqueNamedKey(nickname);
    }

     public static void createSharedSecret(String nickname, KeyGenAlgorithm alg, int keySize)
        throws NotInitializedException, TokenException, Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        SymmetricKey sharedSecretKey = CryptoUtil.generateKey(
                token,
                alg,
                keySize,
                sess_key_usages,
                false, cm.FIPSEnabled() /* sensitive */);

        sharedSecretKey.setNickName(nickname);
    }

    public static void deleteSharedSecret(String nickname) throws NotInitializedException, TokenException,
            InvalidKeyException {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyManager km = new KeyManager(token);
        km.deleteUniqueNamedKey(nickname);
    }

    public static SymmetricKey createDes3SessionKeyOnInternal() throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);

        SymmetricKey.Usage[] usages = new SymmetricKey.Usage[4];
        usages[0] = SymmetricKey.Usage.WRAP;
        usages[1] = SymmetricKey.Usage.UNWRAP;
        usages[2] = SymmetricKey.Usage.ENCRYPT;
        usages[3] = SymmetricKey.Usage.DECRYPT;

        kg.setKeyUsages(usages);
        kg.temporaryKeys(true);

        return kg.generate();
    }

    public static SymmetricKey createAESSessionKeyOnInternal(int keySize) throws Exception {

        String method = "CryptoUtil.createAESSessionKeyOnInternal ";
        logger.debug(method + "Entering... keySize: " + keySize);

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

        SymmetricKey sessionKey = CryptoUtil.generateKey(
                token,
                KeyGenAlgorithm.AES,
                keySize,
                sess_key_usages,
                true, cm.FIPSEnabled() /* sensitive */);


        return sessionKey;
    }

    // Return a list of two wrapped keys:
    // first element: temp DES3 key wrapped by cert ,
    // second element: shared secret wrapped by temp DES3 key
    public static List<byte[]> exportSharedSecret(String nickname, java.security.cert.X509Certificate wrappingCert,
            SymmetricKey wrappingKey) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        List<byte[]> listWrappedKeys = new ArrayList<>();

        KeyManager km = new KeyManager(token);
        if (!km.uniqueNamedKeyExists(nickname)) {
            throw new IOException("Shared secret " + nickname + " does not exist");
        }

        SymmetricKey sharedSecretKey = null;

        try {
            sharedSecretKey = getSymKeyByName(token, nickname);
        } catch (Exception e) {
            sharedSecretKey = null;
        }

        if (sharedSecretKey == null) {
            throw new IOException("Shared secret " + nickname + " does not exist");
        }

        PublicKey pub = wrappingCert.getPublicKey();
        PK11PubKey pubK = PK11PubKey.fromSPKI(pub.getEncoded());

        //Wrap the temp DES3 key with the cert
        byte[] wrappedKey = wrapUsingPublicKey(token, pubK, wrappingKey, KeyWrapAlgorithm.RSA);
        listWrappedKeys.add(wrappedKey);
        //Use the DES3 key to wrap the shared secret

        byte[] wrappedSharedSecret = wrapUsingSymmetricKey(token, wrappingKey, sharedSecretKey, null,
                KeyWrapAlgorithm.DES3_ECB);
        listWrappedKeys.add(wrappedSharedSecret);

        if (listWrappedKeys.size() != 2) {
            throw new IOException("Can't write out shared secret data to export for nickname: " + nickname);
        }

        return listWrappedKeys;
    }

    // Return a list of two wrapped keys:
    // first element: temp AES key wrapped by cert ,
    // second element: shared secret wrapped by temp AES key

    public static List<byte[]> exportSharedSecret(String nickname, java.security.cert.X509Certificate wrappingCert,
            SymmetricKey wrappingKey, boolean useOAEPKeyWrap) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        String method = "CrytoUtil.exportSharedSecret";
        List<byte[]> listWrappedKeys = new ArrayList<byte[]>();

        logger.debug(method + " nickname: " + nickname);

        SymmetricKey sharedSecretKey = null;

        try {
            sharedSecretKey = getSymKeyByName(token, nickname);
        } catch (Exception e) {
            logger.debug(method + " can't find shared secret: " + nickname);
            throw new IOException("Shared secret " + nickname + " does not exist");
        }

        PublicKey pub = wrappingCert.getPublicKey();
        PK11PubKey pubK = PK11PubKey.fromSPKI(pub.getEncoded());

        //Wrap the temp AES key with the cert
        byte[] wrappedKey = wrapUsingPublicKey(token, pubK, wrappingKey, useOAEPKeyWrap ? KeyWrapAlgorithm.RSA_OAEP: KeyWrapAlgorithm.RSA);

        listWrappedKeys.add(wrappedKey);
        //Use the AES key to wrap the shared secret

        KeyWrapAlgorithm  wrapAlg = KeyWrapAlgorithm.AES_CBC_PAD;
        int ivLen = wrapAlg.getBlockSize();
        byte[] iv = new byte[ivLen];

        IVParameterSpec ivsp = new IVParameterSpec(iv);

        byte[] wrappedSharedSecret = wrapUsingSymmetricKey(token, wrappingKey, sharedSecretKey, ivsp, wrapAlg);

        listWrappedKeys.add(wrappedSharedSecret);

        if (listWrappedKeys.size() != 2) {
            throw new IOException("Can't write out shared secret data to export for nickname: " + nickname);
        }

        return listWrappedKeys;
    }

     public static List<byte[]> exportSharedSecretWithAES(String nickname, java.security.cert.X509Certificate wrappingCert,
            SymmetricKey wrappingKey,boolean useOAEPKeyWrap) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        String method = "CrytoUtil.exportSharedSecret";
        List<byte[]> listWrappedKeys = new ArrayList<byte[]>();

        logger.debug(method + " nickname: " + nickname);

        SymmetricKey sharedSecretKey = null;

        try {
            sharedSecretKey = getSymKeyByName(token, nickname);
        } catch (Exception e) {
            logger.debug(method + " can't find shared secret: " + nickname);
            throw new IOException("Shared secret " + nickname + " does not exist");
        }

        PublicKey pub = wrappingCert.getPublicKey();
        PK11PubKey pubK = PK11PubKey.fromSPKI(pub.getEncoded());

        //Wrap the temp AES key with the cert
        byte[] wrappedKey = wrapUsingPublicKey(token, pubK, wrappingKey, useOAEPKeyWrap ? KeyWrapAlgorithm.RSA_OAEP: KeyWrapAlgorithm.RSA);

        listWrappedKeys.add(wrappedKey);
        //Use the AES key to wrap the shared secret

        KeyWrapAlgorithm  wrapAlg = KeyWrapAlgorithm.AES_CBC_PAD;
        int ivLen = wrapAlg.getBlockSize();
        byte[] iv = new byte[ivLen];

        IVParameterSpec ivsp = new IVParameterSpec(iv);

        byte[] wrappedSharedSecret = wrapUsingSymmetricKey(token, wrappingKey, sharedSecretKey, ivsp, wrapAlg);

        listWrappedKeys.add(wrappedSharedSecret);

        if (listWrappedKeys.size() != 2) {
            throw new IOException("Can't write out shared secret data to export for nickname: " + nickname);
        }

        return listWrappedKeys;
    }

    public static void importSharedSecret(byte[] wrappedSessionKey,byte[] wrappedSharedSecret,String subsystemCertNickname,String sharedSecretNickname) throws Exception, NotInitializedException, TokenException,
            NoSuchAlgorithmException, ObjectNotFoundException, InvalidKeyException, InvalidAlgorithmParameterException,
            IOException {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        String method = "CryptoUtil.importSharedSecret ";
        logger.debug(method + " nickname: " + sharedSecretNickname);

        KeyManager km = new KeyManager(token);
        if (km.uniqueNamedKeyExists(sharedSecretNickname)) {
            throw new IOException("Shared secret " + sharedSecretNickname + " already exists");
        }

        //Unwrap session key

        KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
        KeyWrapper keyWrapOAEP = token.getKeyWrapper(KeyWrapAlgorithm.RSA_OAEP);
        logger.debug(method + " subsytemCertNickname: " + subsystemCertNickname);
        System.out.println(method + " subsytemCertNickname: " + subsystemCertNickname);

        X509Certificate cert = cm.findCertByNickname(subsystemCertNickname);
        logger.debug(method + " subsystemCert: " + cert);
        PrivateKey subsystemPrivateKey = cm.findPrivKeyByCert(cert);
        keyWrap.initUnwrap(subsystemPrivateKey, null);

        SymmetricKey unwrappedSessionKey = null;
        //Since we don't know if aes was used to wrap the key, try with and without.
        try {
            unwrappedSessionKey =  keyWrap.unwrapSymmetric(wrappedSessionKey, SymmetricKey.AES,
                0);
        } catch(Exception e) {
            System.out.println(method + " exception found, trying RSA-OAEP: " + e);
           //Since the first attempt is with RSA, try it with RSA-OAEP, to possibly appease our hsm
            OAEPParameterSpec config = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            keyWrapOAEP.initUnwrap(subsystemPrivateKey,config);
            System.out.println("About to unwrap session key with private key, using OAEP");
            unwrappedSessionKey = keyWrapOAEP.unwrapSymmetric(wrappedSessionKey, SymmetricKey.AES,
            SymmetricKey.Usage.UNWRAP, 0);
        }

        //Unwrap shared secret permanently with session key
        EncryptionAlgorithm encAlg = EncryptionAlgorithm.AES_CBC_PAD;
        int ivLen = encAlg.getIVLength();
        byte[] iv = new byte[ivLen];

        IVParameterSpec ivsp = new IVParameterSpec(iv);

        byte[] unwrappedSharedSecret = decryptUsingSymmetricKey(token, ivsp, wrappedSharedSecret,
            unwrappedSessionKey, encAlg);
        SymmetricKey importedSharedSecret =  unwrapAESSKeyFromBytes(token, unwrappedSharedSecret, true);
        importedSharedSecret.setNickName(sharedSecretNickname);
    }

    public static SymmetricKey getSymKeyByName(CryptoToken token, String name) throws Exception {

        String method = "CryptoUtil.getSymKeyByName:";
        if (token == null || name == null) {
            throw new Exception(method + "Invalid input data!");
        }
        SymmetricKey[] keys;

        try {
            keys = token.getCryptoStore().getSymmetricKeys();
        } catch (TokenException e) {
            throw new Exception(method + "Can't get the list of symmetric keys!");
        }
        int len = keys.length;
        for (int i = 0; i < len; i++) {
            SymmetricKey cur = keys[i];
            if (cur != null) {
                if (name.equals(cur.getNickName())) {
                    return cur;
                }
            }
        }

        return null;
    }

    public static String[] getECcurves() {
        return ecCurves;
    }

    public static Vector<String> getECKeyCurve(X509Key key) throws Exception {
        AlgorithmId algid = key.getAlgorithmId();
        //logger.debug("CryptoUtil: getECKeyCurve: algid ="+ algid);

        /*
         * Get raw string representation of alg parameters, will give
         * us the curve OID.
         */
        String params = null;
        if (algid != null) {
            params = algid.getParametersString();
        }

        if ((params != null) && (params.startsWith("OID."))) {
            params = params.substring(4);
        }

        //logger.debug("CryptoUtil: getECKeyCurve: EC key OID ="+ params);
        return ecOIDs.get(params);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //generic crypto operations
    //////////////////////////////////////////////////////////////////////////////////////////////

    public static byte[] decryptUsingSymmetricKey(CryptoToken token, IVParameterSpec ivspec, byte[] encryptedData,
            SymmetricKey wrappingKey, EncryptionAlgorithm encryptionAlgorithm) throws Exception {
        Cipher decryptor = token.getCipherContext(encryptionAlgorithm);
        decryptor.initDecrypt(wrappingKey, ivspec);
        return decryptor.doFinal(encryptedData);
    }

    public static byte[] encryptUsingSymmetricKey(CryptoToken token, SymmetricKey wrappingKey, byte[] data,
            EncryptionAlgorithm alg, IVParameterSpec ivspec)
            throws Exception {
        Cipher cipher = token.getCipherContext(alg);
        cipher.initEncrypt(wrappingKey, ivspec);
        return cipher.doFinal(data);
    }

    public static WrappingParams getWrappingParams(
            KeyWrapAlgorithm kwAlg,
            byte[] iv,
            boolean useOAEP) throws Exception {

        IVParameterSpec ivps = iv != null ? new IVParameterSpec(iv) : null;
        KeyWrapAlgorithm rsaKeyWrapAlg = KeyWrapAlgorithm.RSA;

        if (useOAEP) {
            rsaKeyWrapAlg = KeyWrapAlgorithm.RSA_OAEP;
        }

        if (kwAlg == KeyWrapAlgorithm.AES_KEY_WRAP_PAD ||
            kwAlg == KeyWrapAlgorithm.AES_CBC_PAD) {
            return new WrappingParams(
                SymmetricKey.AES, KeyGenAlgorithm.AES,128 ,
                rsaKeyWrapAlg, EncryptionAlgorithm.AES_128_CBC_PAD,
                kwAlg, ivps, ivps);
        }

        if (kwAlg == KeyWrapAlgorithm.AES_KEY_WRAP) {
            return new WrappingParams(
                SymmetricKey.AES, KeyGenAlgorithm.AES, 128,
                rsaKeyWrapAlg, EncryptionAlgorithm.AES_128_CBC,
                kwAlg, ivps, ivps);
        }

        if (kwAlg == KeyWrapAlgorithm.DES3_CBC_PAD) {
            return new WrappingParams(
                    SymmetricKey.DES3, KeyGenAlgorithm.DES3, 168,
                    rsaKeyWrapAlg, EncryptionAlgorithm.DES3_CBC_PAD,
                    KeyWrapAlgorithm.DES3_CBC_PAD,
                    ivps, ivps);
        }

        if (kwAlg == KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP) {
            return new WrappingParams(
                SymmetricKey.AES, KeyGenAlgorithm.AES, 128,
                rsaKeyWrapAlg, EncryptionAlgorithm.AES_128_KEY_WRAP_KWP,
                kwAlg, ivps, ivps);
        }

        throw new Exception("Invalid encryption algorithm: " + kwAlg);
    }

    public static byte[] wrapUsingSymmetricKey(CryptoToken token, SymmetricKey wrappingKey, SymmetricKey data,
            IVParameterSpec ivspec, KeyWrapAlgorithm alg) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(alg);
        wrapper.initWrap(wrappingKey, ivspec);
        return wrapper.wrap(data);
    }

    public static byte[] wrapUsingSymmetricKey(CryptoToken token, SymmetricKey wrappingKey, PrivateKey data,
            IVParameterSpec ivspec, KeyWrapAlgorithm alg) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(alg);
        wrapper.initWrap(wrappingKey, ivspec);
        return wrapper.wrap(data);
    }

    public static byte[] wrapUsingPublicKey(CryptoToken token, PublicKey wrappingKey, SymmetricKey data,
            KeyWrapAlgorithm alg) throws Exception {
        String method = "CryptoUtil.wrapUsingPublicKey ";
        KeyWrapper rsaWrap = token.getKeyWrapper(alg);
        logger.debug(method + " KeyWrapAlg: " + alg);
        if (alg.equals(KeyWrapAlgorithm.RSA_OAEP)) {
            OAEPParameterSpec config = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsaWrap.initWrap(wrappingKey, config);

        } else {
            rsaWrap.initWrap(wrappingKey, null);
        }

        return rsaWrap.wrap(data);
    }

    public static SymmetricKey unwrap(CryptoToken token, SymmetricKey.Type keyType,
            int strength, SymmetricKey.Usage usage, SymmetricKey wrappingKey, byte[] wrappedData,
            KeyWrapAlgorithm wrapAlgorithm, IVParameterSpec wrappingIV) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(wrapAlgorithm);
        wrapper.initUnwrap(wrappingKey, wrappingIV);
        return wrapper.unwrapSymmetric(wrappedData, keyType, usage, strength / 8);
    }

    public static SymmetricKey unwrap(CryptoToken token, SymmetricKey.Type keyType,
            int strength, SymmetricKey.Usage usage, PrivateKey wrappingKey, byte[] wrappedData,
            KeyWrapAlgorithm wrapAlgorithm) throws Exception {
        KeyWrapper keyWrapper = token.getKeyWrapper(wrapAlgorithm);
        String method = "CryptoUtil.unwrap";
        logger.debug(method + " KeyWrapAlg: " + wrapAlgorithm);

        if (wrapAlgorithm.equals(KeyWrapAlgorithm.RSA_OAEP)) {
            OAEPParameterSpec config = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            keyWrapper.initUnwrap(wrappingKey, config);
        } else {
            keyWrapper.initUnwrap(wrappingKey, null);
        }

        return keyWrapper.unwrapSymmetric(wrappedData, keyType, usage, strength / 8);
    }

    public static PrivateKey unwrap(CryptoToken token, PublicKey pubKey, boolean temporary,
            SymmetricKey wrappingKey, byte[] wrappedData, KeyWrapAlgorithm wrapAlgorithm, IVParameterSpec wrapIV)
            throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(wrapAlgorithm);
        wrapper.initUnwrap(wrappingKey, wrapIV);

        // Get the key type for unwrapping the private key.
        PrivateKey.Type keyType = null;
        if (pubKey.getAlgorithm().equalsIgnoreCase("RSA")) {
            keyType = PrivateKey.RSA;
        } else if (pubKey.getAlgorithm().equalsIgnoreCase("DSA")) {
            keyType = PrivateKey.DSA;
        } else if (pubKey.getAlgorithm().equalsIgnoreCase("EC")) {
            keyType = PrivateKey.EC;
        }

        PrivateKey pk = null;
        if (temporary) {
            pk = wrapper.unwrapTemporaryPrivate(wrappedData,
                    keyType, pubKey);
        } else {
            pk = wrapper.unwrapPrivate(wrappedData,
                    keyType, pubKey);
        }
        return pk;
    }

     public static SymmetricKey unwrapAESSKeyFromBytes(CryptoToken token, byte[] inputKeyArray,
            boolean isPerm)
            throws Exception {

        byte[] finalInputKeyArray = inputKeyArray;
        String method = "CryptoUtil.unwrapAESKeyFromBytes: ";

        logger.debug(method + "begins:  isPerm: " + isPerm);
	//support 128 or 256 bits aes
        if(inputKeyArray.length > 32) {
            throw new Exception(method + "invalid input data size.");
        }

        KeyGenerator kg;
        SymmetricKey finalAESKey;
        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            kg.setKeyUsages(sess_key_usages);
            kg.temporaryKeys(true);
            kg.initialize(128);
            SymmetricKey tempKey = kg.generate();

            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);

            int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength];
            }

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = encryptor.doFinal(finalInputKeyArray);

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap.initUnwrap(tempKey, new IVParameterSpec(iv));

            if(isPerm)
                finalAESKey = keyWrap.unwrapSymmetricPerm(wrappedKey, SymmetricKey.AES, 16);
            else
                finalAESKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES, 16);

        } catch (Exception e) {
            throw new Exception(method + " Can't unwrap key onto token!");
        }

        return finalAESKey;
    }

    // Testing only for use in dev / debugging if needed./
    public static SymmetricKey unwrapDESKeyFromBytes(CryptoToken token, byte[] inputKeyArray,
            boolean isPerm)
            throws Exception {

        String method = "CryptoUtil.unwrapDESKeyFromBytes: ";

        logger.debug(method + "begins:  isPerm: " + isPerm);
        if(inputKeyArray.length > 24) {
            throw new Exception(method + "invalid input data size.");
        }

        KeyGenerator kg;
        SymmetricKey finalDESKey;
        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            kg.setKeyUsages(sess_key_usages);
            kg.temporaryKeys(true);
            kg.initialize(128);
            SymmetricKey tempKey = kg.generate();

            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC_PAD);

            int ivLength = EncryptionAlgorithm.AES_128_CBC_PAD.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength];
            }

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = encryptor.doFinal( getDesParity(inputKeyArray));

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC_PAD);
            keyWrap.initUnwrap(tempKey, new IVParameterSpec(iv));

            if(isPerm)
                finalDESKey = keyWrap.unwrapSymmetricPerm(wrappedKey, SymmetricKey.DES3, 24);
            else
                finalDESKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.DES3, 24);

        } catch (Exception e) {
            throw new Exception(method + " Can't unwrap key onto token!" + e);
        }

        return finalDESKey;
    }

    /**
     * for CMC encryptedPOP
     */
    public static EnvelopedData createEnvelopedData(byte[] encContent, byte[] encSymKey)
            throws Exception {
        String method = "CryptoUtl: createEnvelopedData: ";
        String msg = "";
        logger.debug(method + "begins");
        if ((encContent == null) ||
                (encSymKey == null)) {
            msg = method + "method parameters cannot be null";
            logger.warn(msg);

            throw new Exception(method + msg);
        }

        // TODO(alee) Replace the below with a random IV that is likely passed in
        byte[] default_iv = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        OBJECT_IDENTIFIER oid = EncryptionAlgorithm.AES_128_CBC.toOID();
        AlgorithmIdentifier aid = new AlgorithmIdentifier(oid, new OCTET_STRING(default_iv));

        EncryptedContentInfo encCInfo = new EncryptedContentInfo(
                ContentInfo.DATA,
                aid,
                new OCTET_STRING(encContent));

        Name name = new Name();
        name.addCommonName("unUsedIssuerName"); //unused; okay for cmc EncryptedPOP
        RecipientInfo recipient = new RecipientInfo(
                new INTEGER(0), //per rfc2315
                new IssuerAndSerialNumber(name, new INTEGER(0)), //unUsed
                new AlgorithmIdentifier(RSA_ENCRYPTION, new NULL()),
                new OCTET_STRING(encSymKey));

        SET recipients = new SET();
        recipients.addElement(recipient);

        return new EnvelopedData(
                new INTEGER(0),
                recipients,
                encCInfo);
    }

    /* PKCS 1 - rsaEncryption */
    public static OBJECT_IDENTIFIER RSA_ENCRYPTION = new OBJECT_IDENTIFIER(new long[] { 1, 2, 840, 113549, 1, 1, 1 });

    /**
     * The following are convenience routines for quick preliminary
     * feature development or test programs that would just take
     * the defaults
     */

    public static String getDefaultHashAlgName() {
        return ("SHA-256");
    }

    public static AlgorithmIdentifier getDefaultHashAlg()
            throws Exception {
        AlgorithmIdentifier hashAlg;
        hashAlg = new AlgorithmIdentifier(CryptoUtil.getHashAlgorithmOID(getDefaultHashAlgName()));
        return hashAlg;
    }

    /**
     * importHmacSha1Key returns a key based on a byte array,
     * which is originally a password. Used for the HMAC Digest algorithms.
     *
     * @param key the byte array representing the original password or secret.
     * @return The JSS SymKey
     *
     */
    @Deprecated(since="11.0.1", forRemoval=true)
    public static Key importHmacSha1Key(byte[] key) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("HmacSHA1", "Mozilla-JSS");
        return factory.generateSecret(new SecretKeySpec(key, "SHA1_HMAC"));
    }

    // The following are useful mapping functions

    /**
     * maps from HMACAlgorithm name to FIPS 180-2 MessageDigest algorithm name
     */
    public static String getHMACtoMessageDigestName(String name) {
        String mdName = name;
        if (name != null) {
            if (name.equals("SHA-256-HMAC")) {
                mdName = "SHA-256";
            } else if (name.equals("SHA-384-HMAC")) {
                mdName = "SHA-384";
            } else if (name.equals("SHA-512-HMAC")) {
                mdName = "SHA-512";
            }
        }

        return mdName;
    }

    /**
     * getHMACAlgorithmOID returns OID of the HMAC algorithm name
     *
     * @param name name of the HMAC algorithm
     * @return OID of the HMAC algorithm
     */
    public static OBJECT_IDENTIFIER getHMACAlgorithmOID(String name)
            throws NoSuchAlgorithmException {
        OBJECT_IDENTIFIER oid = null;
        if (name != null) {
            if (name.equals("SHA-256-HMAC")) {
                oid = (HMACAlgorithm.SHA256).toOID();
            } else if (name.equals("SHA-384-HMAC")) {
                oid = (HMACAlgorithm.SHA384).toOID();
            } else if (name.equals("SHA-512-HMAC")) {
                oid = (HMACAlgorithm.SHA512).toOID();
            }
        }
        if (oid == null) {
            throw new NoSuchAlgorithmException();
        }
        return oid;
    }

    /**
     * getHashAlgorithmOID returns OID of the hashing algorithm name
     *
     * @param name name of the hashing algorithm
     * @return OID of the hashing algorithm
     *
     */
    public static OBJECT_IDENTIFIER getHashAlgorithmOID(String name)
            throws NoSuchAlgorithmException {
        OBJECT_IDENTIFIER oid = null;
        if (name != null) {
            if (name.equals("SHA-256")) {
                oid = (DigestAlgorithm.SHA256).toOID();
            } else if (name.equals("SHA-384")) {
                oid = (DigestAlgorithm.SHA384).toOID();
            } else if (name.equals("SHA-512")) {
                oid = (DigestAlgorithm.SHA512).toOID();
            }
        }
        if (oid == null) {
            throw new NoSuchAlgorithmException();
        }
        return oid;
    }

    /**
     * getNameFromHashAlgorithm returns the hashing algorithm name
     * from input Algorithm
     *
     * @param ai the hashing algorithm AlgorithmIdentifier
     * @return name of the hashing algorithm
     *
     */
    public static String getNameFromHashAlgorithm(AlgorithmIdentifier ai)
            throws NoSuchAlgorithmException {
        logger.debug("CryptoUtil: getNameFromHashAlgorithm: " + ai.getOID().toString());
        if (ai != null) {
            if (ai.getOID().equals((DigestAlgorithm.SHA256).toOID())) {
                return "SHA-256";
            } else if (ai.getOID().equals((DigestAlgorithm.SHA384).toOID())) {
                return "SHA-384";
            } else if (ai.getOID().equals((DigestAlgorithm.SHA512).toOID())) {
                return "SHA-512";
            }
        }
        throw new NoSuchAlgorithmException();
    }

    /**
     * Maps from HMACAlgorithm name to JSS Provider HMAC Alg name.
     */
    public static String getHMACAlgName(String name) {
        logger.debug("CrytoUtil: getHMaCAlgName: name: " + name);
        String mdName = "HmacSHA256";
        if (name != null) {
            if (name.equals("SHA-256-HMAC")) {
                mdName = "HmacSHA256";
            } else if (name.equals("SHA-384-HMAC")) {
                mdName = "HmacSHAS384";
            } else if (name.equals("SHA-512-HMAC")) {
                mdName = "HmacSHA512";
            }
        }

        logger.debug("CrytoUtil: getHMaCAlgName: returning: " + mdName);
        return mdName;
    }

    /*
     * Useful method to map KeyWrap algorithms to an OID.
     * This is not yet defined within JSS, although it will be valuable to do
     * so.  The hard thing though is that the KeyWrapAlgorithms in JSS do not take
     * KEK key size into account for algorithms like AES.  We assume 128 bits in
     * this case.
     *
     * This is used in the generation of CRMF requests, and will be correlated to
     * the subsequent reverse mapping method below.
     */
    public static OBJECT_IDENTIFIER getOID(KeyWrapAlgorithm kwAlg) throws NoSuchAlgorithmException {
        String name = kwAlg.toString();
        if (name.equals(KeyWrapAlgorithm.AES_KEY_WRAP_PAD.toString()))
            return KeyWrapAlgorithm.AES_KEY_WRAP_PAD_OID;
        if (name.equals(KeyWrapAlgorithm.AES_KEY_WRAP.toString()))
            return KeyWrapAlgorithm.AES_KEY_WRAP_OID;
        if (name.equals(KeyWrapAlgorithm.AES_CBC_PAD.toString()))
            return KeyWrapAlgorithm.AES_CBC_PAD_OID;
        if (name.equals(KeyWrapAlgorithm.DES3_CBC_PAD.toString()))
            return KeyWrapAlgorithm.DES_CBC_PAD_OID;
        if (name.equals(KeyWrapAlgorithm.DES_CBC_PAD.toString()))
            return KeyWrapAlgorithm.DES_CBC_PAD_OID;
        if (name.equals(KeyWrapAlgorithm.AES_KEY_WRAP_PAD_KWP.toString()))
            return KeyWrapAlgorithm.AES_KEY_WRAP_KWP_OID;
        throw new NoSuchAlgorithmException();
    }

    public static String mapSignatureAlgorithmToInternalName(SignatureAlgorithm alg) throws NoSuchAlgorithmException {
        String method = "CryptoUtil.mapSignatureAlgorithmToInternalName ";
        if (alg == null)
            throw new NoSuchAlgorithmException(method + alg);
        String algname = alg.toString();
        if (algname.equals(SignatureAlgorithm.RSASignatureWithMD5Digest.toString()))
            return "MD5withRSA";
        else if (algname.equals(SignatureAlgorithm.RSASignatureWithMD2Digest.toString()))
            return "MD2withRSA";
        else if (algname.equals(SignatureAlgorithm.RSASignatureWithSHA1Digest.toString()))
            return "SHA1withRSA";
        else if (algname.equals(SignatureAlgorithm.DSASignatureWithSHA1Digest.toString()))
            return "SHA1withDSA";
        else if (algname.equals(SignatureAlgorithm.RSASignatureWithSHA256Digest.toString()))
            return "SHA256withRSA";
        else if (algname.equals(SignatureAlgorithm.RSASignatureWithSHA384Digest.toString()))
            return "SHA384withRSA";
        else if (algname.equals(SignatureAlgorithm.RSASignatureWithSHA512Digest.toString()))
            return "SHA512withRSA";
        else if (algname.equals(SignatureAlgorithm.ECSignatureWithSHA1Digest.toString()))
            return "SHA1withEC";
        else if (algname.equals(SignatureAlgorithm.ECSignatureWithSHA256Digest.toString()))
            return "SHA256withEC";
        else if (algname.equals(SignatureAlgorithm.ECSignatureWithSHA384Digest.toString()))
            return "SHA384withEC";
        else if (algname.equals(SignatureAlgorithm.ECSignatureWithSHA512Digest.toString()))
            return "SHA512withEC";
        else if (algname.equals(SignatureAlgorithm.RSAPSSSignatureWithSHA256Digest.toString()))
            return "SHA256withRSA/PSS";
        else if (algname.equals(SignatureAlgorithm.RSAPSSSignatureWithSHA384Digest.toString()))
            return "SHA384withRSA/PSS";
        else if (algname.equals(SignatureAlgorithm.RSAPSSSignatureWithSHA512Digest.toString()))
            return "SHA512withRSA/PSS";

        throw new NoSuchAlgorithmException(method + alg);
    }

    public static  byte[] getDesParity(byte[] key) throws Exception {
        String method = "CryptoUtil.getDesParity";
        if (key == null || (key.length != 16 &&
                key.length != 24)) {
            throw new Exception(method + " Incorrect input key !");
        }

        byte[] desKey = new byte[key.length];

        for (int i = 0; i < key.length; i++) {
            int index = key[i] & 0xff;
            int finalIndex = index >> 1;

            byte val = (byte) parityTable[finalIndex];
            desKey[i] = val;

        }

        return desKey;
    }

    public static KeyPairGeneratorSpi.Usage[] generateUsage(String usage) {
        return Arrays.stream(usage.toUpperCase().split(",")).map(String::trim)
                .map(KeyPairGeneratorSpi.Usage::valueOf).toArray(KeyPairGeneratorSpi.Usage[]::new);

    }

    public static SymmetricKey.Usage[] generateSymmetricKeyUsage(String usage) {
        return Arrays.stream(usage.toUpperCase().split(",")).map(String::trim)
                .map(SymmetricKey.Usage::valueOf).toArray(SymmetricKey.Usage[]::new);

    }
}

// START ENABLE_ECC
// This following can be removed when JSS with ECC capability
// is integrated.
class CryptoAlgorithm extends Algorithm {
    protected CryptoAlgorithm(int oidIndex, String name) {
        super(oidIndex, name);
    }
}

class CryptoKeyPairAlgorithm extends KeyPairAlgorithm {
    protected CryptoKeyPairAlgorithm(int oidIndex, String name, Algorithm algFamily) {
        super(oidIndex, name, algFamily);
    }
}

class CryptoSignatureAlgorithm extends SignatureAlgorithm {
    protected CryptoSignatureAlgorithm(int oidIndex, String name,
            SignatureAlgorithm signingAlg, DigestAlgorithm digestAlg,
            OBJECT_IDENTIFIER oid) {
        super(oidIndex, name, signingAlg, digestAlg, oid);
    }
}
// END ENABLE_ECC
