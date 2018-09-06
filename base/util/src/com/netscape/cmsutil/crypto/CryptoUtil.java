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
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.SecretDecoderRing.KeyManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.NULL;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenCertificate;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11ECPublicKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs7.IssuerAndSerialNumber;
import org.mozilla.jss.pkcs7.RecipientInfo;
import org.mozilla.jss.pkix.cms.ContentInfo;
import org.mozilla.jss.pkix.cms.EncryptedContentInfo;
import org.mozilla.jss.pkix.cms.EnvelopedData;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant;
import org.mozilla.jss.ssl.SSLSocket.SSLVersionRange;
import org.mozilla.jss.util.Base64OutputStream;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

import netscape.security.pkcs.PKCS10;
import netscape.security.pkcs.PKCS10Attribute;
import netscape.security.pkcs.PKCS10Attributes;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.PKCS9Attribute;
import netscape.security.pkcs.ParsingException;
import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.util.WrappingParams;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.Extensions;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X500Signer;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

@SuppressWarnings("serial")
public class CryptoUtil {

    private static Logger logger = LoggerFactory.getLogger(CryptoUtil.class);

    public static enum SSLVersion {
        SSL_3_0(SSLVersionRange.ssl3),
        TLS_1_0(SSLVersionRange.tls1_0),
        TLS_1_1(SSLVersionRange.tls1_1),
        TLS_1_2(SSLVersionRange.tls1_2);

        public int value;

        SSLVersion(int value) {
            this.value = value;
        }
    }

    public final static int KEY_ID_LENGTH = 20;

    public final static String INTERNAL_TOKEN_NAME = "internal";
    public final static String INTERNAL_TOKEN_FULL_NAME = "Internal Key Storage Token";

    public static final int LINE_COUNT = 76;

    static public final Integer[] clientECCiphers = {
        SSLSocket.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    };
    static public List<Integer> clientECCipherList = new ArrayList<Integer>(Arrays.asList(clientECCiphers));

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


    private final static HashMap<String, Vector<String>> ecOIDs = new HashMap<String, Vector<String>>();
    static {
        ecOIDs.put("1.2.840.10045.3.1.7", new Vector<String>() {
            {
                add("nistp256");
                add("secp256r1");
            }
        });
        ecOIDs.put("1.3.132.0.34", new Vector<String>() {
            {
                add("nistp384");
                add("secp384r1");
            }
        });
        ecOIDs.put("1.3.132.0.35", new Vector<String>() {
            {
                add("nistp521");
                add("secp521r1");
            }
        });
        ecOIDs.put("1.3.132.0.1", new Vector<String>() {
            {
                add("sect163k1");
                add("nistk163");
            }
        });
        ecOIDs.put("1.3.132.0.2", new Vector<String>() {
            {
                add("sect163r1");
            }
        });
        ecOIDs.put("1.3.132.0.15", new Vector<String>() {
            {
                add("sect163r2");
                add("nistb163");
            }
        });
        ecOIDs.put("1.3.132.0.24", new Vector<String>() {
            {
                add("sect193r1");
            }
        });
        ecOIDs.put("1.3.132.0.25", new Vector<String>() {
            {
                add("sect193r2");
            }
        });
        ecOIDs.put("1.3.132.0.26", new Vector<String>() {
            {
                add("sect233k1");
                add("nistk233");
            }
        });
        ecOIDs.put("1.3.132.0.27", new Vector<String>() {
            {
                add("sect233r1");
                add("nistb233");
            }
        });
        ecOIDs.put("1.3.132.0.3", new Vector<String>() {
            {
                add("sect239k1");
            }
        });
        ecOIDs.put("1.3.132.0.16", new Vector<String>() {
            {
                add("sect283k1");
                add("nistk283");
            }
        });
        ecOIDs.put("1.3.132.0.17", new Vector<String>() {
            {
                add("sect283r1");
                add("nistb283");
            }
        });
        ecOIDs.put("1.3.132.0.36", new Vector<String>() {
            {
                add("sect409k1");
                add("nistk409");
            }
        });
        ecOIDs.put("1.3.132.0.37", new Vector<String>() {
            {
                add("sect409r1");
                add("nistb409");
            }
        });
        ecOIDs.put("1.3.132.0.38", new Vector<String>() {
            {
                add("sect571k1");
                add("nistk571");
            }
        });
        ecOIDs.put("1.3.132.0.39", new Vector<String>() {
            {
                add("sect571r1");
                add("nistb571");
            }
        });
        ecOIDs.put("1.3.132.0.9", new Vector<String>() {
            {
                add("secp160k1");
            }
        });
        ecOIDs.put("1.3.132.0.8", new Vector<String>() {
            {
                add("secp160r1");
            }
        });
        ecOIDs.put("1.3.132.0.30", new Vector<String>() {
            {
                add("secp160r2");
            }
        });
        ecOIDs.put("1.3.132.0.31", new Vector<String>() {
            {
                add("secp192k1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.1", new Vector<String>() {
            {
                add("secp192r1");
                add("nistp192");
                add("prime192v1");
            }
        });
        ecOIDs.put("1.3.132.0.32", new Vector<String>() {
            {
                add("secp224k1");
            }
        });
        ecOIDs.put("1.3.132.0.33", new Vector<String>() {
            {
                add("secp224r1");
                add("nistp224");
            }
        });
        ecOIDs.put("1.3.132.0.10", new Vector<String>() {
            {
                add("secp256k1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.2", new Vector<String>() {
            {
                add("prime192v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.3", new Vector<String>() {
            {
                add("prime192v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.4", new Vector<String>() {
            {
                add("prime239v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.5", new Vector<String>() {
            {
                add("prime239v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.6", new Vector<String>() {
            {
                add("prime239v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.1", new Vector<String>() {
            {
                add("c2pnb163v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.2", new Vector<String>() {
            {
                add("c2pnb163v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.3", new Vector<String>() {
            {
                add("c2pnb163v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.4", new Vector<String>() {
            {
                add("c2pnb176v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.5", new Vector<String>() {
            {
                add("c2tnb191v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.6", new Vector<String>() {
            {
                add("c2tnb191v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.7", new Vector<String>() {
            {
                add("c2tnb191v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.10", new Vector<String>() {
            {
                add("c2pnb208w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.11", new Vector<String>() {
            {
                add("c2tnb239v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.12", new Vector<String>() {
            {
                add("c2tnb239v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.13", new Vector<String>() {
            {
                add("c2tnb239v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.16", new Vector<String>() {
            {
                add("c2pnb272w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.17", new Vector<String>() {
            {
                add("c2pnb304w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.19", new Vector<String>() {
            {
                add("c2pnb368w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.20", new Vector<String>() {
            {
                add("c2tnb431r1");
            }
        });
        ecOIDs.put("1.3.132.0.6", new Vector<String>() {
            {
                add("secp112r1");
            }
        });
        ecOIDs.put("1.3.132.0.7", new Vector<String>() {
            {
                add("secp112r2");
            }
        });
        ecOIDs.put("1.3.132.0.28", new Vector<String>() {
            {
                add("secp128r1");
            }
        });
        ecOIDs.put("1.3.132.0.29", new Vector<String>() {
            {
                add("secp128r2");
            }
        });
        ecOIDs.put("1.3.132.0.4", new Vector<String>() {
            {
                add("sect113r1");
            }
        });
        ecOIDs.put("1.3.132.0.5", new Vector<String>() {
            {
                add("sect113r2");
            }
        });
        ecOIDs.put("1.3.132.0.22", new Vector<String>() {
            {
                add("sect131r1");
            }
        });
        ecOIDs.put("1.3.132.0.23", new Vector<String>() {
            {
                add("sect131r2");
            }
        });
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
     * Generates a RSA key pair.
     * @throws Exception
     */
    public static KeyPair generateRSAKeyPair(String tokenName, int keysize)
            throws Exception {
        CryptoToken token = getKeyStorageToken(tokenName);
        return generateRSAKeyPair(token, keysize);
    }

    public static KeyPair generateRSAKeyPair(CryptoToken token, int keysize) throws Exception {
        KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        kg.initialize(keysize);
        return kg.genKeyPair();
    }

    public static boolean isECCKey(X509Key key) {
        String keyAlgo = key.getAlgorithm();
        if (keyAlgo.equals("EC") ||
                keyAlgo.equals("OID.1.2.840.10045.44")) { // ECC
            return true;
        }
        return false;
    }

    /**
     * Generates an ecc key pair.
     */
    public static KeyPair generateECCKeyPair(String token, int keysize)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, keysize, null, null);
    }

    public static KeyPair generateECCKeyPair(String token, int keysize,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, keysize, usage_ops, usage_mask,
            false, -1, -1);
    }

    /*
     * temporary, sensitive, and extractable usages are per defined in
     * JSS pkcs11/PK11KeyPairGenerator.java
     */
    public static KeyPair generateECCKeyPair(String token, int keysize,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask,
           boolean temporary, int sensitive, int extractable)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {

        CryptoToken t = getKeyStorageToken(token);

        KeyPairAlgorithm alg = KeyPairAlgorithm.EC;
        KeyPairGenerator keygen = t.getKeyPairGenerator(alg);

        keygen.setKeyPairUsages(usage_ops, usage_mask);
        keygen.initialize(keysize);
        keygen.setKeyPairUsages(usage_ops, usage_mask);
        keygen.temporaryPairs(temporary);

        if (sensitive == 1 )
            keygen.sensitivePairs(true);
        else if (sensitive == 0)
            keygen.sensitivePairs(false);

        if (extractable == 1 )
            keygen.extractablePairs(true);
        else if (extractable == 0)
            keygen.extractablePairs(false);

        keygen.initialize(keysize);

        KeyPair pair = keygen.genKeyPair();

        return pair;
    }

    /**
     * Generates an ecc key pair by curve name
     */
    public static KeyPair generateECCKeyPair(String token, String curveName)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, curveName, null, null);
    }

    public static KeyPair generateECCKeyPair(CryptoToken token, String curveName)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, curveName, null, null);
    }

    public static KeyPair generateECCKeyPair(String token, String curveName,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getKeyStorageToken(token);
        return generateECCKeyPair(t, curveName, usage_ops, usage_mask);
    }

    public static KeyPair generateECCKeyPair(String token, String curveName,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask,
           boolean temporary, int sensitive, int extractable)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getKeyStorageToken(token);
        return generateECCKeyPair(t, curveName, usage_ops, usage_mask,
            temporary, sensitive, extractable);
    }


    public static KeyPair generateECCKeyPair(CryptoToken token, String curveName,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        return generateECCKeyPair(token, curveName, usage_ops, usage_mask,
            false, -1, -1);
    }

    /*
     * temporary, sensitive, and extractable usages are per defined in
     * JSS pkcs11/PK11KeyPairGenerator.java
     */
    public static KeyPair generateECCKeyPair(CryptoToken token, String curveName,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_ops,
           org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usage_mask,
           boolean temporary, int sensitive, int extractable)
        throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {

        KeyPairAlgorithm alg = KeyPairAlgorithm.EC;
        KeyPairGenerator keygen = token.getKeyPairGenerator(alg);

        keygen.setKeyPairUsages(usage_ops, usage_mask);
        keygen.setKeyPairUsages(usage_ops, usage_mask);
        keygen.temporaryPairs(temporary);

        if (sensitive == 1 )
            keygen.sensitivePairs(true);
        else if (sensitive == 0)
            keygen.sensitivePairs(false);

        if (extractable == 1 )
            keygen.extractablePairs(true);
        else if (extractable == 0)
            keygen.extractablePairs(false);

//        System.out.println("CryptoUtil: generateECCKeyPair: curve = " + curveName);
        int curveCode = 0;
        try {
            curveCode = keygen.getCurveCodeByName(curveName);
        } catch (Exception e) {
//            System.out.println("CryptoUtil: generateECCKeyPair: " + e.toString());
            throw new NoSuchAlgorithmException();
        }
        keygen.initialize(curveCode);

//        System.out.println("CryptoUtil: generateECCKeyPair: after KeyPairGenerator initialize with:" + curveName);
        KeyPair pair = keygen.genKeyPair();

        return pair;
    }

    public static void setSSLStreamVersionRange(SSLVersion min, SSLVersion max) throws SocketException {
        SSLVersionRange range = new SSLVersionRange(min.value, max.value);
        SSLSocket.setSSLVersionRangeDefault(SSLProtocolVariant.STREAM, range);
    }

    public static void setSSLDatagramVersionRange(SSLVersion min, SSLVersion max) throws SocketException {
        SSLVersionRange range = new SSLVersionRange(min.value, max.value);
        SSLSocket.setSSLVersionRangeDefault(SSLProtocolVariant.DATA_GRAM, range);
    }

    private static HashMap<String, Integer> cipherMap = new HashMap<String, Integer>();
    static {
        // SSLv2
        cipherMap.put("SSL2_RC4_128_WITH_MD5", SSLSocket.SSL2_RC4_128_WITH_MD5);
        cipherMap.put("SSL2_RC4_128_EXPORT40_WITH_MD5",
                SSLSocket.SSL2_RC4_128_EXPORT40_WITH_MD5);
        cipherMap.put("SSL2_RC2_128_CBC_WITH_MD5",
                SSLSocket.SSL2_RC2_128_CBC_WITH_MD5);
        cipherMap.put("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
                SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5);
        cipherMap.put("SSL2_IDEA_128_CBC_WITH_MD5",
                SSLSocket.SSL2_IDEA_128_CBC_WITH_MD5);
        cipherMap.put("SSL2_DES_64_CBC_WITH_MD5",
                SSLSocket.SSL2_DES_64_CBC_WITH_MD5);
        cipherMap.put("SSL2_DES_192_EDE3_CBC_WITH_MD5",
                SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5);

        // SSLv3
        cipherMap.put("SSL3_RSA_WITH_NULL_MD5",
                SSLSocket.SSL3_RSA_WITH_NULL_MD5);
        cipherMap.put("SSL3_RSA_WITH_NULL_SHA",
                SSLSocket.SSL3_RSA_WITH_NULL_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_RC4_40_MD5",
                SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5);
        cipherMap.put("SSL3_RSA_WITH_RC4_128_MD5",
                SSLSocket.SSL3_RSA_WITH_RC4_128_MD5);
        cipherMap.put("SSL3_RSA_WITH_RC4_128_SHA",
                SSLSocket.SSL3_RSA_WITH_RC4_128_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
                SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
        cipherMap.put("SSL3_RSA_WITH_IDEA_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_IDEA_CBC_SHA);
        cipherMap.put("SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_RSA_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_DSS_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DH_DSS_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DH_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DH_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DH_RSA_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DHE_DSS_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DHE_RSA_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5",
                SSLSocket.SSL3_DH_ANON_EXPORT_WITH_RC4_40_MD5);
        cipherMap.put("SSL3_DH_ANON_WITH_RC4_128_MD5",
                SSLSocket.SSL3_DH_ANON_WITH_RC4_128_MD5);
        cipherMap.put("SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA",
                SSLSocket.SSL3_DH_ANON_EXPORT_WITH_DES40_CBC_SHA);
        cipherMap.put("SSL3_DH_ANON_WITH_DES_CBC_SHA",
                SSLSocket.SSL3_DH_ANON_WITH_DES_CBC_SHA);
        cipherMap.put("SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL3_DH_ANON_WITH_3DES_EDE_CBC_SHA);

        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_NULL_SHA",
                SSLSocket.SSL3_FORTEZZA_DMS_WITH_NULL_SHA);
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA",
                SSLSocket.SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
        cipherMap.put("SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA",
                SSLSocket.SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA);

        cipherMap.put("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("SSL_RSA_FIPS_WITH_DES_CBC_SHA",
                SSLSocket.SSL_RSA_FIPS_WITH_DES_CBC_SHA);

        // TLS
        cipherMap.put("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
                SSLSocket.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA);
        cipherMap.put("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
                SSLSocket.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA);

        cipherMap.put("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
                SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
                SSLSocket.TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_RC4_128_SHA",
                SSLSocket.TLS_DHE_DSS_WITH_RC4_128_SHA);

        cipherMap.put("TLS_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_DSS_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DH_DSS_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DH_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_DH_ANON_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_DH_ANON_WITH_AES_128_CBC_SHA);

        cipherMap.put("TLS_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_DSS_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DH_DSS_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        cipherMap.put("TLS_DH_ANON_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_DH_ANON_WITH_AES_256_CBC_SHA);

        // ECC
        cipherMap.put("TLS_ECDH_ECDSA_WITH_NULL_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDHE_ECDSA_WITH_NULL_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDHE_RSA_WITH_NULL_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);

        cipherMap.put("TLS_ECDH_anon_WITH_NULL_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_NULL_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_RC4_128_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_RC4_128_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
        cipherMap.put("TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
                SSLSocket.TLS_ECDH_anon_WITH_AES_256_CBC_SHA);

        // TLSv1_2
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                SSLSocket.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        cipherMap.put("TLS_RSA_WITH_NULL_SHA256",
                SSLSocket.TLS_RSA_WITH_NULL_SHA256);
        cipherMap.put("TLS_RSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_RSA_WITH_AES_256_CBC_SHA256",
                SSLSocket.TLS_RSA_WITH_AES_256_CBC_SHA256);
        cipherMap.put("TLS_RSA_WITH_SEED_CBC_SHA",
                SSLSocket.TLS_RSA_WITH_SEED_CBC_SHA);
        cipherMap.put("TLS_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_RSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        cipherMap.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                SSLSocket.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);

    }

    public static void setClientCiphers(String list) throws SocketException {

        if (list == null) {
            // use default
            setDefaultSSLCiphers();
            return;
        }

        String ciphers[] = list.split(",");
        if (ciphers.length == 0) return;

        unsetSSLCiphers();

        for (String cipher : ciphers) {
            setSSLCipher(cipher, true);
        }
    }

    public static void setSSLCiphers(String ciphers) throws SocketException {

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
    }

    public static void setSSLCipher(String cipher, boolean enabled) throws SocketException {

        Integer cipherID;
        if (cipher.toLowerCase().startsWith("0x")) {
            cipherID = Integer.parseInt(cipher.substring(2), 16);

        } else {
            cipherID = cipherMap.get(cipher);
            if (cipherID == null) {
                throw new SocketException("Unsupported cipher: " + cipher);
            }
        }

        SSLSocket.setCipherPreferenceDefault(cipherID, enabled);
    }

    public static void setDefaultSSLCiphers() throws SocketException {

        int ciphers[] = SSLSocket.getImplementedCipherSuites();
        if (ciphers == null) return;

        for (int cipher : ciphers) {

            boolean enabled = SSLSocket.getCipherPreferenceDefault(cipher);
            //System.out.println("CryptoUtil: cipher '0x" +
            //    Integer.toHexString(ciphers[j]) + "'" + " enabled? " +
            //    enabled);

            // make sure SSLv2 ciphers are not enabled
            if ((cipher & 0xfff0) == 0xff00) {

                if (!enabled) continue;

                //System.out.println("CryptoUtil: disabling SSLv2 NSS Cipher '0x" +
                //    Integer.toHexString(ciphers[j]) + "'");
                SSLSocket.setCipherPreferenceDefault(cipher, false);
                continue;
            }

            // unlike RSA ciphers, ECC ciphers are not enabled by default
            if (!enabled && clientECCipherList.contains(cipher)) {
                //System.out.println("CryptoUtil: enabling ECC NSS Cipher '0x" +
                //    Integer.toHexString(ciphers[j]) + "'");
                SSLSocket.setCipherPreferenceDefault(cipher, true);
            }
        }
    }

    /*
     * unset all implemented cipehrs; for enforcing strict list of ciphers
     */
    public static void unsetSSLCiphers() throws SocketException {

        int cipherIDs[] = SSLSocket.getImplementedCipherSuites();
        if (cipherIDs == null) return;

        for (int cipherID : cipherIDs) {
            SSLSocket.setCipherPreferenceDefault(cipherID, false);
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

    public static byte[] base64Decode(String s) throws IOException {
        // BASE64Decoder base64 = new BASE64Decoder();
        // byte[] d = base64.decodeBuffer(s);
        byte[] d = Utils.base64decode(s);

        return d;
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

    public static String getPKCS10FromKey(String dn,
                    byte modulus[], byte exponent[], byte prikdata[])
              throws IOException,
                     InvalidKeyException,
                     TokenException,
                     NoSuchProviderException,
                     CertificateException,
                     SignatureException,
                     CryptoManager.NotInitializedException,
                     NoSuchAlgorithmException {
        X509Key x509key = getPublicX509Key(modulus, exponent);
        PrivateKey prik = findPrivateKeyFromID(prikdata);
        PKCS10 pkcs10 = createCertificationRequest(dn, x509key, prik);
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        return bs.toString();
    }

    public static String getPKCS10FromKey(String dn,
                    byte modulus[], byte exponent[], byte prikdata[], String alg)
              throws IOException,
                     InvalidKeyException,
                     TokenException,
                     NoSuchProviderException,
                     CertificateException,
                     SignatureException,
                     CryptoManager.NotInitializedException,
                     NoSuchAlgorithmException {
        X509Key x509key = getPublicX509Key(modulus, exponent);
        PrivateKey prik = findPrivateKeyFromID(prikdata);
        PKCS10 pkcs10 = createCertificationRequest(dn, x509key, prik, alg);
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        return bs.toString();
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
    /**
     * Sorts certificate chain from root to leaf.
     *
     * This method sorts an array of certificates (e.g. from a PKCS #7
     * data) that represents a certificate chain from root to leaf
     * according to the subject DNs and issuer DNs.
     *
     * The input array is a set of certificates that are part of a
     * chain but not in specific order.
     *
     * The result is a new array that contains the certificate chain
     * sorted from root to leaf. The input array is unchanged.
     *
     * @param certs input array of certificates
     * @return new array containing sorted certificates
     */
    public static java.security.cert.X509Certificate[] sortCertificateChain(java.security.cert.X509Certificate[] certs) throws Exception {

        // lookup map: subject DN -> cert
        Map<String, java.security.cert.X509Certificate> certMap = new LinkedHashMap<>();

        // hierarchy map: subject DN -> issuer DN
        Map<String, String> parentMap = new HashMap<>();

        // reverse hierarchy map: issuer DN -> subject DN
        Map<String, String> childMap = new HashMap<>();

        // build maps
        for (java.security.cert.X509Certificate cert : certs) {

            String subjectDN = cert.getSubjectDN().toString();
            String issuerDN = cert.getIssuerDN().toString();

            if (certMap.containsKey(subjectDN)) {
                throw new Exception("Duplicate certificate: " + subjectDN);
            }

            certMap.put(subjectDN, cert);

            // ignore self-signed certificate
            if (subjectDN.equals(issuerDN)) continue;

            if (childMap.containsKey(issuerDN)) {
                throw new Exception("Branched chain: " + issuerDN);
            }

            parentMap.put(subjectDN, issuerDN);
            childMap.put(issuerDN, subjectDN);
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Certificates:");
            for (String subjectDN : certMap.keySet()) {
                logger.debug(" - " + subjectDN);

                String parent = parentMap.get(subjectDN);
                if (parent != null) logger.debug("   parent: " + parent);

                String child = childMap.get(subjectDN);
                if (child != null) logger.debug("   child: " + child);
            }
        }

        // find leaf cert
        List<String> leafCerts = new ArrayList<>();

        for (String subjectDN : certMap.keySet()) {

            // if cert has a child, skip
            if (childMap.containsKey(subjectDN)) continue;

            // found leaf cert
            leafCerts.add(subjectDN);
        }

        if (leafCerts.isEmpty()) {
            throw new Exception("Unable to find leaf certificate");
        }

        if (leafCerts.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (String subjectDN : leafCerts) {
                if (sb.length() > 0) sb.append(", ");
                sb.append("[" + subjectDN + "]");
            }
            throw new Exception("Multiple leaf certificates: " + sb);
        }

        // build sorted chain
        LinkedList<java.security.cert.X509Certificate> chain = new LinkedList<>();

        // start from leaf
        String current = leafCerts.get(0);

        while (current != null) {

            java.security.cert.X509Certificate cert = certMap.get(current);

            // add to the beginning of chain
            chain.addFirst(cert);

            // follow parent to root
            current = parentMap.get(current);
        }

        return chain.toArray(new java.security.cert.X509Certificate[chain.size()]);
    }

    public static java.security.cert.X509Certificate[] sortCertificateChain(
            java.security.cert.X509Certificate[] certs,
            boolean reverse) throws Exception {

        certs = sortCertificateChain(certs);

        if (reverse) {
            ArrayUtils.reverse(certs);
        }

        return certs;
    }

    public static void importCertificateChain(byte[] bytes)
             throws IOException,
                    CryptoManager.NotInitializedException,
                    TokenException,
                    CertificateEncodingException,
                    CertificateException {

        CryptoManager manager = CryptoManager.getInstance();

        X509Certificate cert = null;

        try {
            // try PKCS7 first
            PKCS7 pkcs7 = new PKCS7(bytes);

            java.security.cert.X509Certificate[] certs = pkcs7.getCertificates();

            if (certs != null) {
                // import PKCS7 certs one by one
                for (int i = 0; i < certs.length; i++) {
                    cert = manager.importCACertPackage(certs[i].getEncoded());
                }
            }

        } catch (ParsingException e) {
            // not PKCS7
        }

        if (cert == null) {
            cert = manager.importCACertPackage(bytes);
        }

        X509Certificate[] certs = manager.buildCertificateChain(cert);
        X509Certificate rootCert = certs[certs.length - 1];

        trustCACert(rootCert);
    }

    public static SEQUENCE parseCRMFMsgs(byte cert_request[])
               throws IOException, InvalidBERException {
        if (cert_request == null) {
            throw new IOException("invalid certificate requests: cert_request null");
        }
        ByteArrayInputStream crmfBlobIn =
                new ByteArrayInputStream(cert_request);
        SEQUENCE crmfMsgs = (SEQUENCE)
                new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(
                        crmfBlobIn);
        return crmfMsgs;
    }

    public static X509Key getX509KeyFromCRMFMsgs(SEQUENCE crmfMsgs)
              throws IOException, NoSuchAlgorithmException,
                  InvalidKeyException, InvalidKeyFormatException {
        if (crmfMsgs == null) {
            throw new IOException("invalid certificate requests: crmfMsgs null");
        }
        int nummsgs = crmfMsgs.size();
        if (nummsgs <= 0) {
            throw new IOException("invalid certificate requests");
        }
        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        return getX509KeyFromCRMFMsg(msg);
    }

    public static X509Key getX509KeyFromCRMFMsg(CertReqMsg crmfMsg)
              throws IOException, NoSuchAlgorithmException,
                  InvalidKeyException, InvalidKeyFormatException {
        CertRequest certreq = crmfMsg.getCertReq();
        CertTemplate certTemplate = certreq.getCertTemplate();
        SubjectPublicKeyInfo spkinfo = certTemplate.getPublicKey();
        PublicKey pkey = spkinfo.toPublicKey();
        X509Key x509key = convertPublicKeyToX509Key(pkey);
        return x509key;
    }

    public static X509Key getPublicX509Key(byte modulus[], byte exponent[])
            throws InvalidKeyException {
        return new netscape.security.provider.RSAPublicKey(new BigInt(modulus),
                new BigInt(exponent));
    }

    public static X509Key getPublicX509ECCKey(byte encoded[])
            throws InvalidKeyException {
        try {
            return X509Key.parse(new DerValue(encoded));
        } catch (IOException e) {
            throw new InvalidKeyException();
        }
    }

    public static X509Key convertPublicKeyToX509Key(PublicKey pubk)
            throws InvalidKeyException {
        X509Key xKey;

        if (pubk instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) pubk;

            xKey = new netscape.security.provider.RSAPublicKey(
                    new BigInt(rsaKey.getModulus()),
                    new BigInt(rsaKey.getPublicExponent()));
        } else if (pubk instanceof PK11ECPublicKey) {
            byte encoded[] = pubk.getEncoded();
            xKey = CryptoUtil.getPublicX509ECCKey(encoded);
        } else {
            // Assert.assert(pubk instanceof DSAPublicKey);
            DSAPublicKey dsaKey = (DSAPublicKey) pubk;
            DSAParams params = dsaKey.getParams();

            xKey = new netscape.security.provider.DSAPublicKey(dsaKey.getY(),
                    params.getP(), params.getQ(), params.getG());
        }
        return xKey;
    }

    public static String getSubjectName(SEQUENCE crmfMsgs)
            throws IOException {
        int nummsgs = crmfMsgs.size();
        if (nummsgs <= 0) {
            throw new IOException("invalid certificate requests");
        }
        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        CertRequest certreq = msg.getCertReq();
        CertTemplate certTemplate = certreq.getCertTemplate();
        Name n = certTemplate.getSubject();
        ByteArrayOutputStream subjectEncStream = new ByteArrayOutputStream();
        n.encode(subjectEncStream);

        byte[] b = subjectEncStream.toByteArray();
        X500Name subject = new X500Name(b);
        return subject.toString();
    }

    /**
     * Creates a Certificate template.
     */
    public static X509CertInfo createX509CertInfo(KeyPair pair,
            int serialno, String issuername, String subjname,
            Date notBefore, Date notAfter)
            throws IOException,
                CertificateException,
                InvalidKeyException {
        return createX509CertInfo(convertPublicKeyToX509Key(pair.getPublic()),
                serialno, issuername, subjname, notBefore, notAfter);
    }

    public static X509CertInfo createX509CertInfo(PublicKey publickey,
            int serialno, String issuername, String subjname,
            Date notBefore, Date notAfter)
            throws IOException,
                CertificateException,
                InvalidKeyException {
        return createX509CertInfo(convertPublicKeyToX509Key(publickey), serialno,
                issuername, subjname, notBefore, notAfter);
    }

    public static X509CertInfo createX509CertInfo(X509Key x509key,
            BigInteger serialno, String issuername, String subjname,
            Date notBefore, Date notAfter)
            throws IOException,
                CertificateException,
                InvalidKeyException {
        // set default; use the other call with "alg" to set algorithm
        String alg = "SHA256withRSA";
        try {
            return createX509CertInfo(x509key, serialno, issuername, subjname, notBefore, notAfter, alg);
        } catch (NoSuchAlgorithmException ex) {
            // for those that calls the old call without alg
            throw new CertificateException("createX509CertInfo old call should not be here");
        }
    }

    public static X509CertInfo createX509CertInfo(X509Key x509key,
            BigInteger serialno, String issuername, String subjname,
            Date notBefore, Date notAfter, String alg)
            throws IOException,
            CertificateException,
            InvalidKeyException,
            NoSuchAlgorithmException {
            CertificateIssuerName issuernameObj =
                    new CertificateIssuerName(new X500Name(issuername));
            return createX509CertInfo(x509key, serialno, issuernameObj, subjname, notBefore, notAfter, alg);
    }

    public static X509CertInfo createX509CertInfo(X509Key x509key,
            BigInteger serialno, CertificateIssuerName issuernameObj, String subjname,
            Date notBefore, Date notAfter, String alg)
            throws IOException,
            CertificateException,
            InvalidKeyException,
            NoSuchAlgorithmException {
        X509CertInfo info = new X509CertInfo();

        info.set(X509CertInfo.VERSION, new
                CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.SERIAL_NUMBER, new
                CertificateSerialNumber(serialno));
        if (issuernameObj != null) {
            info.set(X509CertInfo.ISSUER,
                    issuernameObj);
        }
        info.set(X509CertInfo.SUBJECT, new
                CertificateSubjectName(new X500Name(subjname)));
        info.set(X509CertInfo.VALIDITY, new
                CertificateValidity(notBefore, notAfter));
        info.set(X509CertInfo.ALGORITHM_ID, new
                CertificateAlgorithmId(AlgorithmId.get(alg)));
        info.set(X509CertInfo.KEY, new CertificateX509Key(x509key));
        info.set(X509CertInfo.EXTENSIONS, new CertificateExtensions());
        return info;
    }

    public static X509CertImpl signECCCert(PrivateKey privateKey,
            X509CertInfo certInfo)
            throws NoSuchTokenException,
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException {
        // set default; use the other call with "alg" to specify algorithm
        String alg = "SHA256withEC";
        return signECCCert(privateKey, certInfo, alg);
    }

    public static X509CertImpl signECCCert(PrivateKey privateKey,
            X509CertInfo certInfo, String alg)
            throws NoSuchTokenException,
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException {
        return signCert(privateKey, certInfo,
                Cert.mapAlgorithmToJss(alg));
    }

    /**
     * Signs certificate.
     */
    public static X509CertImpl signCert(PrivateKey privateKey,
            X509CertInfo certInfo, String alg)
            throws NoSuchTokenException,
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException {
        return signCert(privateKey, certInfo,
                 Cert.mapAlgorithmToJss(alg));
    }

    public static X509CertImpl signCert(PrivateKey privateKey,
            X509CertInfo certInfo, SignatureAlgorithm sigAlg)
            throws NoSuchTokenException,
                CryptoManager.NotInitializedException,
                NoSuchAlgorithmException,
                NoSuchTokenException,
                TokenException,
                InvalidKeyException,
                SignatureException,
                IOException,
                CertificateException {

        DerInputStream ds = new DerInputStream(ASN1Util.encode(sigAlg.toOID()));
        ObjectIdentifier sigAlgOID = new ObjectIdentifier(ds);
        AlgorithmId aid = new AlgorithmId(sigAlgOID);
        certInfo.set(X509CertInfo.ALGORITHM_ID,
                new CertificateAlgorithmId(aid));

        org.mozilla.jss.crypto.PrivateKey priKey = privateKey;
        CryptoToken token = priKey.getOwningToken();

        DerOutputStream tmp = new DerOutputStream();

        certInfo.encode(tmp);
        Signature signer = token.getSignatureContext(sigAlg);

        signer.initSign(priKey);
        signer.update(tmp.toByteArray());
        byte signed[] = signer.sign();

        aid.encode(tmp);
        tmp.putBitString(signed);
        try (DerOutputStream out = new DerOutputStream()) {
            out.write(DerValue.tag_Sequence, tmp);
            X509CertImpl signedCert = new X509CertImpl(out.toByteArray());
            return signedCert;
        }
    }

    /**
     * Creates a PKCS#10 request.
     */
    public static PKCS10 createCertificationRequest(String subjectName,
            X509Key pubk, PrivateKey prik)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        // give default
        String alg = "SHA256withRSA";
        if (isECCKey(pubk)) {
            alg = "SHA256withEC";
        }
        return createCertificationRequest(subjectName, pubk, prik, alg);
    }

    public static PKCS10 createCertificationRequest(String subjectName,
            X509Key pubk, PrivateKey prik, String alg)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        return createCertificationRequest(subjectName, pubk, prik, alg, null);
    }

    /*
     * This createCertificationRequest() allows extensions to be added to the CSR
     */
    public static PKCS10 createCertificationRequest(String subjectName,
            KeyPair keyPair, Extensions exts)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, IOException, CertificateException,
            SignatureException {
        String method = "CryptoUtil: createCertificationRequest: ";

        String alg = "SHA256withRSA";
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);
        if (pubk instanceof RSAPublicKey) {
            alg = "SHA256withRSA";
        } else if (isECCKey(key)) {
            alg = "SHA256withEC";
        } else {
            throw new NoSuchAlgorithmException(method + alg);
        }

        return createCertificationRequest(
                subjectName, key, (org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate(),
                alg, exts);
    }

    public static PKCS10 createCertificationRequest(String subjectName,
            X509Key pubk, PrivateKey prik, String alg, Extensions exts)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, IOException, CertificateException,
            SignatureException {
        X509Key key = pubk;
        java.security.Signature sig = java.security.Signature.getInstance(alg,
                "Mozilla-JSS");

        sig.initSign(prik);
        PKCS10 pkcs10 = null;

        if (exts != null && !exts.isEmpty()) {
            PKCS10Attribute attr = new PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID,
                    exts);
            PKCS10Attributes attrs = new PKCS10Attributes();

            System.out.println("PKCS10: createCertificationRequest: adding attribute name =" +
                    attr.getAttributeValue().getName());
            attrs.setAttribute(attr.getAttributeValue().getName(), attr);

            pkcs10 = new PKCS10(key, attrs);
        } else {
            pkcs10 = new PKCS10(key);
        }
        X500Name name = new X500Name(subjectName);
        X500Signer signer = new X500Signer(sig, name);

        pkcs10.encodeAndSign(signer);
        return pkcs10;
    }

    public static KeyIdentifier createKeyIdentifier(KeyPair keypair)
            throws NoSuchAlgorithmException, InvalidKeyException {
        String method = "CryptoUtil: createKeyIdentifier: ";
        System.out.println(method + "begins");

        X509Key subjectKeyInfo = convertPublicKeyToX509Key(
                keypair.getPublic());

        byte[] hash = generateKeyIdentifier(subjectKeyInfo.getKey());

        if (hash == null) {
            System.out.println(method +
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
            byte[] hash = md.digest();

            return hash;
        } catch (NoSuchAlgorithmException e) {
            msg = method + e;
            System.out.println(msg);
        } catch (Exception e) {
            msg = method + e;
            System.out.println(msg);
        }
        return null;
    }

    public static String getSKIString(X509CertImpl cert) throws IOException {

        SubjectKeyIdentifierExtension ext = (SubjectKeyIdentifierExtension)
                cert.getExtension(PKIXExtensions.SubjectKey_Id.toString());

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
        netscape.security.util.PrettyPrintFormat pp = new netscape.security.util.PrettyPrintFormat(":", 20);
        return pp.toHexString(ski).trim();
    }

    /**
     * Creates a PKCS#10 request.
     */
    public static PKCS10 createCertificationRequest(String subjectName,
            KeyPair keyPair)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        String alg;
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);
        if (pubk instanceof RSAPublicKey) {
            alg = "SHA256withRSA";
        } else if (isECCKey(key)) {
            alg = "SHA256withEC";
        } else {
            // Assert.assert(pubk instanceof DSAPublicKey);
            alg = "DSA";
        }
        return createCertificationRequest(subjectName, keyPair, alg);
    }

    public static PKCS10 createCertificationRequest(String subjectName,
            KeyPair keyPair, String alg)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, IOException, CertificateException,
                SignatureException {
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);

        java.security.Signature sig = java.security.Signature.getInstance(alg,
                "Mozilla-JSS");

        sig.initSign(keyPair.getPrivate());

        PKCS10 pkcs10 = new PKCS10(key);

        X500Name name = new X500Name(subjectName);
        X500Signer signer = new X500Signer(sig, name);

        pkcs10.encodeAndSign(signer);

        return pkcs10;
    }

    /*
     * get extention from  PKCS10 request
     */
    public static netscape.security.x509.Extension getExtensionFromPKCS10(PKCS10 pkcs10, String extnName)
            throws IOException, CertificateException {
        Extension extn = null;

        String method = "CryptoUtiil: getExtensionFromPKCS10: ";
        System.out.println(method + "begins");

        PKCS10Attributes attributeSet = pkcs10.getAttributes();
        if (attributeSet == null) {
            System.out.println(method + "attributeSet not found");
            return null;
        }
        PKCS10Attribute attr = attributeSet.getAttribute("extensions");
        if (attr == null) {
            System.out.println(method + "extensions attribute not found");
            return null;
        }
        System.out.println(method + attr.toString());

        CertAttrSet cas = attr.getAttributeValue();
        if (cas == null) {
            System.out.println(method + "CertAttrSet not found in PKCS10Attribute");
            return null;
        }

        Enumeration<String> en = cas.getAttributeNames();
        while (en.hasMoreElements()) {
            String name = en.nextElement();
            System.out.println(method + " checking extension in request:" + name);
            if (name.equals(extnName)) {
                System.out.println(method + "extension matches");
                extn = (Extension)cas.get(name);
            }
        }

        System.out.println(method + "ends");
        return extn;
    }

    /*
     * get extension from CRMF cert request (CertTemplate)
     */
    public static netscape.security.x509.Extension getExtensionFromCertTemplate(CertTemplate certTemplate, ObjectIdentifier csOID) {
        //ObjectIdentifier csOID = PKIXExtensions.SubjectKey_Id;
        OBJECT_IDENTIFIER jssOID =
                new OBJECT_IDENTIFIER(csOID.toString());
/*
        return getExtensionFromCertTemplate(certTemplate, jssOID);
    }
    public static netscape.security.x509.Extension getExtensionFromCertTemplate(CertTemplate certTemplate, org.mozilla.jss.asn1.OBJECT_IDENTIFIER jssOID) {
*/

        String method = "CryptoUtil: getSKIExtensionFromCertTemplate: ";
        Extension extn = null;

       /*
        * there seems to be an issue with constructor in Extension
        * when feeding SubjectKeyIdentifierExtension;
        * Special-case it
        */
        OBJECT_IDENTIFIER SKIoid =
                new OBJECT_IDENTIFIER(PKIXExtensions.SubjectKey_Id.toString());

        if (certTemplate.hasExtensions()) {
            int numexts = certTemplate.numExtensions();
            for (int j = 0; j < numexts; j++) {
                 org.mozilla.jss.pkix.cert.Extension jssext =
                         certTemplate.extensionAt(j);
                 org.mozilla.jss.asn1.OBJECT_IDENTIFIER extnoid =
                         jssext.getExtnId();
                 System.out.println(method + "checking extension in request:" + extnoid.toString());
                 if (extnoid.equals(jssOID)) {
                     System.out.println(method + "extension found");
                     try {
                       if (jssOID.equals(SKIoid)) {
                         System.out.println(method + "SKIoid == jssOID");
                         extn =
                             new SubjectKeyIdentifierExtension(false, jssext.getExtnValue().toByteArray());
                       } else {
                         System.out.println(method + "SKIoid != jssOID");
                         extn =
                             new netscape.security.x509.Extension(csOID, false, jssext.getExtnValue().toByteArray());
                       }
                     } catch (IOException e) {
                       System.out.println(method + e);
                     }
                 }
            }
        } else {
            System.out.println(method + "no extension found");
        }

        return extn;
    }

    public static void unTrustCert(InternalCertificate cert) {
        // remove TRUSTED_CA
        int flag = cert.getSSLTrust();

        flag ^= InternalCertificate.VALID_CA;
        cert.setSSLTrust(flag);
    }

    /**
     * Trusts a certificate by nickname.
     */
    public static void trustCertByNickname(String nickname)
            throws CryptoManager.NotInitializedException,
                TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate certs[] = cm.findCertsByNickname(nickname);

        if (certs == null) {
            return;
        }
        for (int i = 0; i < certs.length; i++) {
            trustCert((InternalCertificate) certs[i]);
        }
    }

    /**
     * Trusts a certificate.
     */
    public static void trustCert(InternalCertificate cert) {
        int flag = InternalCertificate.VALID_CA | InternalCertificate.TRUSTED_CA
                | InternalCertificate.USER
                | InternalCertificate.TRUSTED_CLIENT_CA;

        cert.setSSLTrust(flag);
        cert.setObjectSigningTrust(flag);
        cert.setEmailTrust(flag);
    }

    public static void trustCACert(X509Certificate cert) {

        // set trust flags to CT,C,C
        InternalCertificate ic = (InternalCertificate) cert;

        ic.setSSLTrust(InternalCertificate.TRUSTED_CA
                | InternalCertificate.TRUSTED_CLIENT_CA
                | InternalCertificate.VALID_CA);

        ic.setEmailTrust(InternalCertificate.TRUSTED_CA
                | InternalCertificate.VALID_CA);

        ic.setObjectSigningTrust(InternalCertificate.TRUSTED_CA
                | InternalCertificate.VALID_CA);
    }

    public static void trustAuditSigningCert(X509Certificate cert) {

        // set trust flags to u,u,Pu
        InternalCertificate ic = (InternalCertificate) cert;

        ic.setSSLTrust(InternalCertificate.USER);

        ic.setEmailTrust(InternalCertificate.USER);

        ic.setObjectSigningTrust(InternalCertificate.USER
                | InternalCertificate.VALID_PEER
                | InternalCertificate.TRUSTED_PEER);
    }

    /**
     * To certificate server point of view, SSL trust is
     * what we referring.
     */
    public static boolean isCertTrusted(InternalCertificate cert) {
        if (isTrust(cert.getSSLTrust()) && isTrust(cert.getObjectSigningTrust())
                && isTrust(cert.getEmailTrust())) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean isTrust(int flag) {
        if (((flag & InternalCertificate.VALID_CA) > 0)
                && ((flag & InternalCertificate.TRUSTED_CA) > 0)
                && ((flag & InternalCertificate.USER) > 0)
                && ((flag & InternalCertificate.TRUSTED_CLIENT_CA) > 0)) {
            return true;
        } else {
            return false;
        }
    }

    public static SymmetricKey generateKey(CryptoToken token, KeyGenAlgorithm alg, int keySize,
            SymmetricKey.Usage[] usages, boolean temporary) throws Exception {
        KeyGenerator kg = token.getKeyGenerator(alg);
        if (usages != null)
            kg.setKeyUsages(usages);
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
    public static boolean compare(byte src[], byte dest[]) {
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
    public static String byte2string(byte id[]) {
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
            throw new IllegalArgumentException(
                    "Unable to encode Key ID: " + Hex.encodeHexString(keyID));
        }

        return new BigInteger(keyID).toString(16);
    }

    /**
     * Converts NSS key ID from a signed, variable-length hexadecimal number
     * into a 20 byte array, which will be identical to the original byte array.
     */
    public static byte[] decodeKeyID(String id) {

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
            byte b = (byte)(value.signum() >= 0 ? 0x00 : 0xff);

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
        if(bytes == null)
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
        if(chars == null)
            return null;

        Charset charset = Charset.forName("UTF-8");
        ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(chars));
        byte[] result = Arrays.copyOf(byteBuffer.array(), byteBuffer.limit());

        if(byteBuffer.hasArray()) {
            byte[] contentsToBeErased = byteBuffer.array();
            CryptoUtil.obscureBytes(contentsToBeErased, "random");
        }
        return result;
    }

    /**
     * Create a jss Password object from a provided byte array.
     */
    public static Password createPasswordFromBytes(byte[] bytes ) {

        if(bytes == null)
            return null;

        char[] pwdChars = bytesToChars(bytes);
        Password password = new Password(pwdChars);
        obscureChars(pwdChars);

        return password;
    }

    /**
     * Retrieves a private key from a unique key ID.
     */
    public static PrivateKey findPrivateKeyFromID(byte id[])
            throws CryptoManager.NotInitializedException,
                TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        @SuppressWarnings("unchecked")
        Enumeration<CryptoToken> enums = cm.getAllTokens();

        while (enums.hasMoreElements()) {
            CryptoToken token = enums.nextElement();
            CryptoStore store = token.getCryptoStore();
            PrivateKey keys[] = store.getPrivateKeys();

            if (keys != null) {
                for (int i = 0; i < keys.length; i++) {
                    if (compare(keys[i].getUniqueID(), id)) {
                        return keys[i];
                    }
                }
            }
        }
        return null;
    }

    /**
     * Retrieves all user certificates from all tokens.
     */
    public static X509CertImpl[] getAllUserCerts()
            throws CryptoManager.NotInitializedException,
                TokenException {
        Vector<X509CertImpl> certs = new Vector<X509CertImpl>();
        CryptoManager cm = CryptoManager.getInstance();
        @SuppressWarnings("unchecked")
        Enumeration<CryptoToken> enums = cm.getAllTokens();

        while (enums.hasMoreElements()) {
            CryptoToken token = enums.nextElement();

            CryptoStore store = token.getCryptoStore();
            org.mozilla.jss.crypto.X509Certificate list[] = store.getCertificates();

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
                } catch (TokenException e) {
                    continue;
                } catch (ObjectNotFoundException e) {
                    continue;
                }
            }
        }
        if (certs.size() == 0) {
            return null;
        } else {
            X509CertImpl c[] = new X509CertImpl[certs.size()];

            certs.copyInto(c);
            return c;
        }
    }

    /**
     * Deletes a private key.
     */
    public static void deletePrivateKey(PrivateKey prikey)
            throws CryptoManager.NotInitializedException, TokenException {

        try {
            CryptoToken token = prikey.getOwningToken();
            CryptoStore store = token.getCryptoStore();

            store.deletePrivateKey(prikey);
        } catch (NoSuchItemOnTokenException e) {
        }
    }

    /**
     * Retrieves a private key by nickname.
     */
    public static PrivateKey getPrivateKey(String nickname)
            throws CryptoManager.NotInitializedException, TokenException {
        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(nickname);
            org.mozilla.jss.crypto.PrivateKey prikey = cm.findPrivKeyByCert(cert);

            return prikey;
        } catch (ObjectNotFoundException e) {
        }
        return null;
    }

    /**
     * Deletes all certificates by a nickname.
     */
    public static void deleteCertificates(String nickname)
            throws TokenException, ObjectNotFoundException,
            NoSuchItemOnTokenException, NotInitializedException {

        CryptoManager manager = CryptoManager.getInstance();
        X509Certificate[] certs = manager.findCertsByNickname(nickname);

        if (certs == null || certs.length == 0) {
            throw new ObjectNotFoundException("Certificate not found: " + nickname);
        }

        for (X509Certificate cert : certs) {

            CryptoToken token;
            if (cert instanceof TokenCertificate) {
                TokenCertificate tokenCert = (TokenCertificate) cert;
                token = tokenCert.getOwningToken();

            } else {
                token = manager.getInternalKeyStorageToken();
            }

            CryptoStore store = token.getCryptoStore();
            store.deleteCert(cert);
        }
    }

    /**
     * Deletes user certificates by a nickname.
     */
    public static void deleteUserCertificates(String nickname)
            throws CryptoManager.NotInitializedException, TokenException {

        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate certs[] = cm.findCertsByNickname(nickname);

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
            } catch (NoSuchItemOnTokenException e) {
            } catch (ObjectNotFoundException e) {
            }
        }
    }

    /**
     * Imports a PKCS#7 certificate chain that includes the user
     * certificate, and trusts the certificate.
     */
    public static X509Certificate importUserCertificateChain(String c,
            String nickname)
            throws CryptoManager.NotInitializedException,
                CryptoManager.NicknameConflictException,
                CryptoManager.UserCertConflictException,
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
            throws CryptoManager.NotInitializedException,
                CertificateEncodingException,
                NoSuchItemOnTokenException,
                TokenException,
                CryptoManager.NicknameConflictException,
                CryptoManager.UserCertConflictException {

        CryptoManager cm = CryptoManager.getInstance();
        return cm.importUserCACertPackage(bytes, nickname);
    }

    public static java.security.cert.X509Certificate[] getX509CertificateFromPKCS7(byte[] b) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        CertificateChain certchain = new CertificateChain();

        certchain.decode(bis);
        java.security.cert.X509Certificate[] certs = certchain.getChain();

        return certs;
    }

    /**
     * Generates a nonce_iv for padding.
     *
     * @return
     * @throws GeneralSecurityException
     */
    public static byte[] getNonceData(int size) throws GeneralSecurityException {
        byte[] iv = new byte[size];

        SecureRandom rnd = CryptoUtil.getRandomNumberGenerator();
        rnd.nextBytes(iv);

        return iv;
    }

    public static SecureRandom getRandomNumberGenerator() throws GeneralSecurityException {
        SecureRandom  rnd = SecureRandom.getInstance("pkcs11prng","Mozilla-JSS");

        return rnd;

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
            Arrays.fill(memory, (byte)0);
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
        PasswordConverter passConverter = new
                    PasswordConverter();

        ByteArrayInputStream inStream = new ByteArrayInputStream(wrappedRecoveredKey);
        cInfo = (EncryptedContentInfo)
                      new EncryptedContentInfo.Template().decode(inStream);

        byte[] decodedData = cInfo.decrypt(pass, passConverter);

        return decodedData;
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
            char []data,
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
        SymmetricKey sessionKey = CryptoUtil.generateKey(
                token,
                params.getSkKeyGenAlgorithm(),
                params.getSkLength(),
                null,
                false);
        byte[] key_data;

        if (passphraseData != null) {

            byte[] secret =  CryptoUtil.charsToBytes(passphraseData);
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
        PKIArchiveOptions options = (PKIArchiveOptions)
                  (new PKIArchiveOptions.Template()).decode(inStream);

        return encoded;
    }

    public static PrivateKey importPKIArchiveOptions(
            CryptoToken token, PrivateKey unwrappingKey,
            PublicKey pubkey, byte[] data)
            throws InvalidBERException, Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        PKIArchiveOptions options = (PKIArchiveOptions) (new PKIArchiveOptions.Template()).decode(in);
        EncryptedKey encKey = options.getEncryptedKey();
        EncryptedValue encVal = encKey.getEncryptedValue();
        AlgorithmIdentifier algId = encVal.getSymmAlg();
        BIT_STRING encSymKey = encVal.getEncSymmKey();
        BIT_STRING encPrivKey = encVal.getEncValue();

        SymmetricKey sk = unwrap(
                token, SymmetricKey.Type.DES3, 0, SymmetricKey.Usage.UNWRAP,
                unwrappingKey, encSymKey.getBits(), KeyWrapAlgorithm.RSA);

        ASN1Value v = algId.getParameters();
        v = ((ANY) v).decodeWith(new OCTET_STRING.Template());
        byte iv[] = ((OCTET_STRING) v).toByteArray();
        IVParameterSpec ivps = new IVParameterSpec(iv);

        return unwrap(token, pubkey, false, sk, encPrivKey.getBits(), KeyWrapAlgorithm.DES3_CBC_PAD, ivps);
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

    public static void deleteSharedSecret(String nickname) throws NotInitializedException, TokenException,
            InvalidKeyException {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        KeyManager km = new KeyManager(token);
        km.deleteUniqueNamedKey(nickname);
    }

    // Return a list of two wrapped keys:
    // first element: temp DES3 key wrapped by cert ,
    // second element: shared secret wrapped by temp DES3 key
    public static List<byte[]> exportSharedSecret(String nickname, java.security.cert.X509Certificate wrappingCert,
            SymmetricKey wrappingKey) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        List<byte[]> listWrappedKeys = new ArrayList<byte[]>();

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

        byte[] wrappedSharedSecret = wrapUsingSymmetricKey(token, wrappingKey, sharedSecretKey, null, KeyWrapAlgorithm.DES3_ECB);
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

        KeyManager km = new KeyManager(token);

        if (km.uniqueNamedKeyExists(sharedSecretNickname)) {
            throw new IOException("Shared secret " + sharedSecretNickname + " already exists");
        }

        //Unwrap session key

        KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
        X509Certificate cert = cm.findCertByNickname(subsystemCertNickname);
        PrivateKey subsystemPrivateKey = cm.findPrivKeyByCert(cert);
        keyWrap.initUnwrap(subsystemPrivateKey, null);

        SymmetricKey unwrappedSessionKey = keyWrap.unwrapSymmetric(wrappedSessionKey, SymmetricKey.DES3,
                0);

        SymmetricKey unwrappedSharedSecret = null;

        //Unwrap shared secret permanently with session key

        KeyWrapper sharedSecretWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
        sharedSecretWrap.initUnwrap(unwrappedSessionKey,null);
        unwrappedSharedSecret = sharedSecretWrap.unwrapSymmetricPerm(wrappedSharedSecret,SymmetricKey.DES3,0 );
        unwrappedSharedSecret.setNickName(sharedSecretNickname);
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
        //System.out.println("CryptoUtil: getECKeyCurve: algid ="+ algid);

        /*
         * Get raw string representation of alg parameters, will give
         * us the curve OID.
         */
        String params =  null;
        if (algid != null) {
            params = algid.getParametersString();
        }

        if ((params != null) && (params.startsWith("OID."))) {
            params = params.substring(4);
        }

        //System.out.println("CryptoUtil: getECKeyCurve: EC key OID ="+ params);
        Vector<String> vect = ecOIDs.get(params);

        return vect;
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
        KeyWrapper rsaWrap = token.getKeyWrapper(alg);
        rsaWrap.initWrap(wrappingKey, null);
        return rsaWrap.wrap(data);
    }

    public static SymmetricKey unwrap(CryptoToken token, SymmetricKey.Type keyType,
            int strength, SymmetricKey.Usage usage, SymmetricKey wrappingKey, byte[] wrappedData,
            KeyWrapAlgorithm wrapAlgorithm, IVParameterSpec wrappingIV) throws Exception {
        KeyWrapper wrapper = token.getKeyWrapper(wrapAlgorithm);
        wrapper.initUnwrap(wrappingKey, wrappingIV);
        return wrapper.unwrapSymmetric(wrappedData, keyType, usage, strength/8);
    }

    public static SymmetricKey unwrap(CryptoToken token, SymmetricKey.Type keyType,
            int strength, SymmetricKey.Usage usage, PrivateKey wrappingKey, byte[] wrappedData,
            KeyWrapAlgorithm wrapAlgorithm) throws Exception {
        KeyWrapper keyWrapper = token.getKeyWrapper(wrapAlgorithm);
        keyWrapper.initUnwrap(wrappingKey, null);

        return keyWrapper.unwrapSymmetric(wrappedData, keyType, usage, strength/8);
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

    /**
     * for CMC encryptedPOP
     */
    public static EnvelopedData createEnvelopedData(byte[] encContent, byte[] encSymKey)
            throws Exception {
        String method = "CryptoUtl: createEnvelopedData: ";
        String msg = "";
        System.out.println(method + "begins");
        if ((encContent == null) ||
                (encSymKey == null)) {
            msg = method + "method parameters cannot be null";
            System.out.println(msg);

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

        EnvelopedData envData = new EnvelopedData(
                new INTEGER(0),
                recipients,
                encCInfo);

        return envData;
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
        if ( oid == null) {
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
        if ( oid == null) {
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
        System.out.println("CryptoUtil: getNameFromHashAlgorithm: " + ai.getOID().toString());
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

    public static final OBJECT_IDENTIFIER KW_AES_KEY_WRAP_PAD = new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.1.8");
    public static final OBJECT_IDENTIFIER KW_AES_CBC_PAD = new OBJECT_IDENTIFIER("2.16.840.1.101.3.4.1.2");
    public static final OBJECT_IDENTIFIER KW_DES_CBC_PAD = new OBJECT_IDENTIFIER("1.2.840.113549.3.7");

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
            return KW_AES_KEY_WRAP_PAD;
        if (name.equals(KeyWrapAlgorithm.AES_CBC_PAD.toString()))
            return KW_AES_CBC_PAD;
        if (name.equals(KeyWrapAlgorithm.DES3_CBC_PAD.toString()))
            return KW_DES_CBC_PAD;
        if (name.equals(KeyWrapAlgorithm.DES_CBC_PAD.toString()))
            return KW_DES_CBC_PAD;

        throw new NoSuchAlgorithmException();
    }

    public static KeyWrapAlgorithm getKeyWrapAlgorithmFromOID(String wrapOID) throws NoSuchAlgorithmException {
        OBJECT_IDENTIFIER oid = new OBJECT_IDENTIFIER(wrapOID);
        if (oid.equals(KW_AES_KEY_WRAP_PAD))
            return KeyWrapAlgorithm.AES_KEY_WRAP_PAD;

        if (oid.equals(KW_AES_CBC_PAD))
            return KeyWrapAlgorithm.AES_CBC_PAD;

        if (oid.equals(KW_DES_CBC_PAD))
            return KeyWrapAlgorithm.DES3_CBC_PAD;

        throw new NoSuchAlgorithmException();
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
