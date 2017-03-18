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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
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
import java.util.List;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.SecretDecoderRing.KeyManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
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
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11ECPublicKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs7.EncryptedContentInfo;
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

import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

import netscape.security.pkcs.PKCS10;
import netscape.security.pkcs.PKCS10Attribute;
import netscape.security.pkcs.PKCS10Attributes;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.PKCS9Attribute;
import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateChain;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateIssuerName;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extensions;
import netscape.security.x509.X500Name;
import netscape.security.x509.X500Signer;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

@SuppressWarnings("serial")
public class CryptoUtil {

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

    public final static String INTERNAL_TOKEN_NAME = "internal";
    public final static String INTERNAL_TOKEN_FULL_NAME = "Internal Key Storage Token";

    public static final String CERTREQ_BEGIN_HEADING = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String CERTREQ_END_HEADING = "-----END CERTIFICATE REQUEST-----";
    public static final int LINE_COUNT = 76;
    public static final String CERT_BEGIN_HEADING = "-----BEGIN CERTIFICATE-----";
    public static final String CERT_END_HEADING = "-----END CERTIFICATE-----";

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
     */
    public static KeyPair generateRSAKeyPair(String token, int keysize)
            throws CryptoManager.NotInitializedException,
                NoSuchTokenException,
                NoSuchAlgorithmException,
                TokenException {
        CryptoToken t = getKeyStorageToken(token);
        KeyPairGenerator g = t.getKeyPairGenerator(KeyPairAlgorithm.RSA);

        g.initialize(keysize);
        KeyPair pair = g.genKeyPair();

        return pair;
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
            setClientCiphers();
            return;
        }

        String ciphers[] = list.split(",");
        if (ciphers.length == 0) return;

        unsetSSLCiphers();

        for (String cipher : ciphers) {

            Integer cipherID = cipherMap.get(cipher);
            if (cipherID == null) continue;

            SSLSocket.setCipherPreferenceDefault(cipherID, true);
        }
    }

    public static void setClientCiphers() throws SocketException {

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
    private static void unsetSSLCiphers() throws SocketException {
        int ciphers[] = SSLSocket.getImplementedCipherSuites();
        try {
            for (int i = 0; ciphers != null && i < ciphers.length; i++) {
                SSLSocket.setCipherPreferenceDefault(ciphers[i], false);
            }
        } catch (Exception e) {
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
        result.append(CERTREQ_BEGIN_HEADING + "\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT) + "\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result.append(content + "\n" + CERTREQ_END_HEADING);
        } else {
            result.append(CERTREQ_END_HEADING);
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
        result.append(CERT_BEGIN_HEADING + "\n");

        while (content.length() >= LINE_COUNT) {
            result.append(content.substring(0, LINE_COUNT) + "\n");
            content = content.substring(LINE_COUNT);
        }
        if (content.length() > 0) {
            result.append(content + "\n" + CERT_END_HEADING);
        } else {
            result.append(CERT_END_HEADING);
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

        if (s.startsWith(CERT_BEGIN_HEADING) && s.endsWith(CERT_END_HEADING)) {
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

        StringBuffer sb = new StringBuffer();
        StringTokenizer st = new StringTokenizer(s, "\r\n ");

        while (st.hasMoreTokens()) {
            String nextLine = st.nextToken();
            nextLine = nextLine.trim();
            sb.append(nextLine);
        }
        return sb.toString();
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

    public static void importCertificateChain(String certchain)
             throws IOException,
                    CryptoManager.NotInitializedException,
                    TokenException,
                    CertificateEncodingException,
                    CertificateException {
        byte[] blah = base64Decode(certchain);
        CryptoManager manager = CryptoManager.getInstance();
        PKCS7 pkcs7 = null;
        try {
            // try PKCS7 first
            pkcs7 = new PKCS7(blah);
        } catch (Exception e) {
        }
        X509Certificate cert = null;
        if (pkcs7 == null) {
            cert = manager.importCACertPackage(blah);
        } else {
            java.security.cert.X509Certificate certsInP7[] =
                    pkcs7.getCertificates();
            if (certsInP7 == null) {
                cert = manager.importCACertPackage(blah);
            } else {
                for (int i = 0; i < certsInP7.length; i++) {
                    // import P7 one by one
                    cert = manager.importCACertPackage(certsInP7[i].getEncoded());
                }
            }
        }
        X509Certificate[] certchains =
                CryptoManager.getInstance().buildCertificateChain(cert);

        if (certchains != null) {
            cert = certchains[certchains.length - 1];
        }

        // set trust flags to CT,C,C
        InternalCertificate icert = (InternalCertificate) cert;
        icert.setSSLTrust(InternalCertificate.TRUSTED_CA
                                    | InternalCertificate.TRUSTED_CLIENT_CA
                                    | InternalCertificate.VALID_CA);
        icert.setEmailTrust(InternalCertificate.TRUSTED_CA
                | InternalCertificate.VALID_CA);
        icert.setObjectSigningTrust(InternalCertificate.TRUSTED_CA
                | InternalCertificate.VALID_CA);
    }

    public static SEQUENCE parseCRMFMsgs(byte cert_request[])
               throws IOException, InvalidBERException {
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
        int nummsgs = crmfMsgs.size();
        if (nummsgs <= 0) {
            throw new IOException("invalid certificate requests");
        }
        CertReqMsg msg = (CertReqMsg) crmfMsgs.elementAt(0);
        CertRequest certreq = msg.getCertReq();
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
            PKCS10Attribute attr = new
                    PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID,
                            exts);
            PKCS10Attributes attrs = new PKCS10Attributes();

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

    public static String byte2string(byte id[]) {
        return new BigInteger(id).toString(16);
    }

    public static byte[] string2byte(String id) {
        return (new BigInteger(id, 16)).toByteArray();
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
    public static void deleteAllCertificates(String nickname)
            throws CryptoManager.NotInitializedException, TokenException {
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate certs[] = cm.findCertsByNickname(nickname);

        if (certs == null) {
            return;
        }
        for (int i = 0; i < certs.length; i++) {
            try {
                X509Certificate cert = certs[i];
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
     * Imports a user certificate, and trusts the certificate.
     */
    public static void importUserCertificate(X509CertImpl cert, String nickname)
            throws CryptoManager.NotInitializedException,
                CertificateEncodingException,
                NoSuchItemOnTokenException,
                TokenException,
                CryptoManager.NicknameConflictException,
                CryptoManager.UserCertConflictException {
        CryptoManager cm = CryptoManager.getInstance();

        cm.importUserCACertPackage(cert.getEncoded(), nickname);
        trustCertByNickname(nickname);
    }

    public static void importUserCertificate(X509CertImpl cert, String nickname,
            boolean trust)
            throws CryptoManager.NotInitializedException,
                CertificateEncodingException,
                NoSuchItemOnTokenException,
                TokenException,
                CryptoManager.NicknameConflictException,
                CryptoManager.UserCertConflictException {
        CryptoManager cm = CryptoManager.getInstance();

        cm.importUserCACertPackage(cert.getEncoded(), nickname);
        if (trust)
            trustCertByNickname(nickname);
    }

    public static java.security.cert.X509Certificate[] getX509CertificateFromPKCS7(byte[] b) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(b);
        CertificateChain certchain = new CertificateChain();

        certchain.decode(bis);
        java.security.cert.X509Certificate[] certs = certchain.getChain();

        return certs;
    }

    /**
     * Generates a nonve_iv for padding.
     *
     * @return
     */
    public static byte[] getNonceData(int size) {
        byte[] iv = new byte[size];
        Random rnd = new Random();
        rnd.nextBytes(iv);

        return iv;
    }

    public static byte[] unwrapUsingPassphrase(byte[] wrappedRecoveredKey, String recoveryPassphrase)
            throws IOException, InvalidBERException, InvalidKeyException, IllegalStateException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, NotInitializedException, TokenException,
            IllegalBlockSizeException, BadPaddingException {
        EncryptedContentInfo cInfo = null;

        //We have to do this to get the decoding to work.
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

    public static byte[] wrapPassphrase(CryptoToken token, String passphrase, IVParameterSpec IV, SymmetricKey sk,
            EncryptionAlgorithm alg)
            throws NoSuchAlgorithmException, TokenException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] wrappedPassphrase = null;
        Cipher encryptor = null;

        encryptor = token.getCipherContext(alg);

        if (encryptor != null) {
            encryptor.initEncrypt(sk, IV);
            wrappedPassphrase = encryptor.doFinal(passphrase.getBytes("UTF-8"));
        } else {
            throw new IOException("Failed to create cipher");
        }

        return wrappedPassphrase;
    }

    public static byte[] wrapSymmetricKey(CryptoManager manager, CryptoToken token, String transportCert,
            SymmetricKey sk) throws Exception {
        byte transport[] = Utils.base64decode(transportCert);
        X509Certificate tcert = manager.importCACertPackage(transport);
        return wrapUsingPublicKey(token, tcert.getPublicKey(), sk, KeyWrapAlgorithm.RSA);
    }

    public static byte[] createPKIArchiveOptions(CryptoManager manager, CryptoToken token, String transportCert,
            SymmetricKey vek, String passphrase, KeyGenAlgorithm keyGenAlg, int symKeySize, IVParameterSpec IV)
            throws Exception {
        byte[] key_data = null;

        //generate session key
        SymmetricKey sk = CryptoUtil.generateKey(token, keyGenAlg, symKeySize, null, false);

        if (passphrase != null) {
            key_data = wrapPassphrase(token, passphrase, IV, sk, EncryptionAlgorithm.DES3_CBC_PAD);
        } else {
            // wrap payload using session key
            key_data = wrapUsingSymmetricKey(token, sk, vek, IV, KeyWrapAlgorithm.DES3_CBC_PAD);
        }

        // wrap session key using transport key
        byte[] session_data = wrapSymmetricKey(manager, token, transportCert, sk);

        return createPKIArchiveOptions(IV, session_data, key_data);
    }

    public static byte[] createPKIArchiveOptions(
            CryptoToken token, PublicKey wrappingKey, PrivateKey toBeWrapped,
            KeyGenAlgorithm keyGenAlg, int symKeySize, IVParameterSpec IV)
            throws Exception {
        SymmetricKey sessionKey = CryptoUtil.generateKey(token, keyGenAlg, symKeySize, null, false);
        byte[] key_data = wrapUsingSymmetricKey(token, sessionKey, toBeWrapped, IV, KeyWrapAlgorithm.DES3_CBC_PAD);

        byte[] session_data = wrapUsingPublicKey(token, wrappingKey, sessionKey, KeyWrapAlgorithm.RSA);
        return createPKIArchiveOptions(IV, session_data, key_data);
    }

    private static byte[] createPKIArchiveOptions(
            IVParameterSpec IV, byte[] session_data, byte[] key_data)
            throws IOException, InvalidBERException {
        // create PKIArchiveOptions structure
        AlgorithmIdentifier algS = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.113549.3.7"),
                new OCTET_STRING(IV.getIV()));
        EncryptedValue encValue = new EncryptedValue(null, algS, new BIT_STRING(session_data, 0), null, null,
                new BIT_STRING(key_data, 0));
        EncryptedKey key = new EncryptedKey(encValue);
        PKIArchiveOptions opt = new PKIArchiveOptions(key);

        byte[] encoded = null;

        //Let's make sure we can decode the encoded PKIArchiveOptions..
        ByteArrayOutputStream oStream = new ByteArrayOutputStream();

        opt.encode(oStream);

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

        SymmetricKey sk = unwrap(token, SymmetricKey.Type.DES3, 0, null, unwrappingKey, encSymKey.getBits(),
                KeyWrapAlgorithm.RSA);

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
        return wrapper.unwrapSymmetric(wrappedData, keyType, usage, strength);
    }

    public static SymmetricKey unwrap(CryptoToken token, SymmetricKey.Type keyType,
            int strength, SymmetricKey.Usage usage, PrivateKey wrappingKey, byte[] wrappedData,
            KeyWrapAlgorithm wrapAlgorithm) throws Exception {
        KeyWrapper keyWrapper = token.getKeyWrapper(wrapAlgorithm);
        keyWrapper.initUnwrap(wrappingKey, null);

        return keyWrapper.unwrapSymmetric(wrappedData, keyType, usage, strength);
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
     * The following are convenience routines for quick preliminary
     * feature development or test programs that would just take
     * the defaults
     */

    private static byte default_iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
    private static IVParameterSpec default_IV = new IVParameterSpec(default_iv);

    // this generates a temporary 128 bit AES symkey with defaults
    public static SymmetricKey generateKey(CryptoToken token) throws Exception {
        return generateKey(token,
//TODO:                KeyGenAlgorithm.AES, 128,
                KeyGenAlgorithm.DES3, 128 /*unused*/,
                null, true);
    }

    // decryptUsingSymmetricKey with default algorithms
    public static byte[] decryptUsingSymmetricKey(CryptoToken token, byte[] encryptedData, SymmetricKey wrappingKey) throws Exception {
        return decryptUsingSymmetricKey(token, default_IV, encryptedData,
                wrappingKey,
                EncryptionAlgorithm.DES3_CBC_PAD);
//TODO:                EncryptionAlgorithm.AES_128_CBC);
    }

    // encryptUsingSymmetricKey with default algorithms
    public static byte[] encryptUsingSymmetricKey(CryptoToken token, SymmetricKey wrappingKey, byte[] data) throws Exception {
        return encryptUsingSymmetricKey(
                token,
                wrappingKey,
                data,
                EncryptionAlgorithm.DES3_CBC_PAD,
//TODO:                EncryptionAlgorithm.AES_128_CBC,
                default_IV);
    }

    // wrapUsingPublicKey using default algorithm
    public static byte[] wrapUsingPublicKey(CryptoToken token, PublicKey wrappingKey, SymmetricKey data) throws Exception {
        return wrapUsingPublicKey(token, wrappingKey, data, KeyWrapAlgorithm.RSA);
    }

    // unwrap sym key using default algorithms
    public static SymmetricKey unwrap(CryptoToken token, SymmetricKey.Usage usage, PrivateKey wrappingKey, byte[] wrappedSymKey) throws Exception {
        return unwrap(
               token,
//TODO:               SymmetricKey.AES,
               SymmetricKey.DES3,
               0,
               usage,
               wrappingKey,
               wrappedSymKey,
               getDefaultKeyWrapAlg());
    }

    public static AlgorithmIdentifier getDefaultEncAlg()
           throws Exception {
        OBJECT_IDENTIFIER oid =
                EncryptionAlgorithm.DES3_CBC.toOID();
//TODO:                EncryptionAlgorithm.AES_128_CBC.toOID();

        AlgorithmIdentifier aid =
                new AlgorithmIdentifier(oid, new OCTET_STRING(default_iv));
        return aid;
    }

    public static String getDefaultHashAlgName() {
        return ("SHA-256");
    }

    public static KeyWrapAlgorithm getDefaultKeyWrapAlg() {
        return KeyWrapAlgorithm.RSA;
    }

    public static AlgorithmIdentifier getDefaultHashAlg()
           throws Exception {
        AlgorithmIdentifier hashAlg;
            hashAlg = new AlgorithmIdentifier(CryptoUtil.getHashAlgorithmOID("SHA-256"));
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
