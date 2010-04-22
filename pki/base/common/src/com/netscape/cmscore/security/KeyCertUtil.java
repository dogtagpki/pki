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
package com.netscape.cmscore.security;


import org.mozilla.jss.asn1.*;

import java.security.PrivateKey;
import java.security.*;
import java.util.*;
import java.security.interfaces.*;
import java.io.IOException;
import java.io.*;
import java.security.cert.CertificateException;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.*;
import java.math.*;
//import java.security.cert.*;
import org.mozilla.jss.crypto.X509Certificate;
//import netscape.security.provider.DSAPublicKey;
// ADDED next line by MLH on 1/9/99
// REMOVED the line added by MLH on 1/10/99
//import netscape.security.provider.RSAPublicKey;
import netscape.security.x509.*;
import netscape.security.extensions.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import org.mozilla.jss.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.CryptoManager.NicknameConflictException;
import org.mozilla.jss.CryptoManager.UserCertConflictException;
import java.security.cert.CertificateEncodingException;
import netscape.ldap.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.security.*;
import com.netscape.cmscore.cert.*;
import com.netscape.cmscore.util.*;
import com.netscape.cmscore.dbs.*;


/**
 * This class provides all the base methods to generate the key for different
 * kinds of certificates.
 * 
 * @author Christine Ho
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class KeyCertUtil {

    public static final String CA_SIGNINGCERT_NICKNAME = "caSigningCert";
    private static final int MAX_DOMESTIC_SSL_KEY_LEN = 4096;
    private static final int MAX_EXPORT_SSL_KEY_LEN = 512;
    private static final int MIN_DSA_KEY_LEN = 512;
    private static final int MAX_DSA_KEY_LEN = 1024;

    public static void checkCertificateExt(String ext) throws EBaseException {
        byte[] b = null;

        if (ext != null) {
            try {

                b = (byte[]) (com.netscape.osutil.OSUtil.AtoB(ext));
                // this b can be "Extension" Or "SEQUENCE OF Extension"
                DerValue b_der = new DerValue(b);

                while (b_der.data.available() != 0) {
                    Extension de = new Extension(b_der.data.getDerValue());
                }
            } catch (IOException e) {
                try {
                    Extension de = new Extension(new DerValue(b));
                } catch (IOException ex) {
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_CERT_EXTENSION"));
                }
            }
        }
    }

    public static String getTokenNames(CryptoManager manager) 
        throws TokenException {
        String tokenList = "";
        Enumeration tokens = manager.getExternalTokens();
        int num = 0;

        while (tokens.hasMoreElements()) {
            CryptoToken c = (CryptoToken) tokens.nextElement();

            if (num++ == 0)
                tokenList = tokenList + c.getName();
            else
                tokenList = tokenList + "," + c.getName();
        }

        if (tokenList.equals(""))
            return Constants.PR_INTERNAL_TOKEN;
        else
            return (tokenList + "," + Constants.PR_INTERNAL_TOKEN);
    }

    public static String base64Encode(byte[] bytes) throws IOException {
        // All this streaming is lame, but Base64OutputStream needs a
        // PrintStream
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Base64OutputStream b64 = new Base64OutputStream(new
                PrintStream(new
                    FilterOutputStream(output)
                )
            );

        b64.write(bytes);
        b64.flush();

        // This is internationally safe because Base64 chars are
        // contained within 8859_1
        return output.toString("8859_1");
    }

    public static byte[] makeDSSParms(BigInteger P, BigInteger Q, BigInteger G)
        throws IOException {

        // Write P, Q, G to a DER stream
        DerOutputStream contents = new DerOutputStream();

        contents.putInteger(new BigInt(P));
        contents.putInteger(new BigInt(Q));
        contents.putInteger(new BigInt(G));

        // Make a sequence from the PQG stream
        DerOutputStream sequence = new DerOutputStream();

        sequence.write(DerValue.tag_Sequence, contents);

        return sequence.toByteArray();
    }

    public static PrivateKey getPrivateKey(String tokenname, String nickname) 
        throws TokenException, EBaseException,
            NoSuchTokenException, NotInitializedException, CertificateException,
            CertificateEncodingException, EBaseException, ObjectNotFoundException {

        /*
         String caNickname = store.getString("ca.signing.tokenname");
         String tokenName = store.getString("ca.signing.cacertnickname");
         */
        X509Certificate cert = getCertificate(tokenname, nickname);
            
        return CryptoManager.getInstance().findPrivKeyByCert(cert);
    }

    public static String getCertSubjectName(String tokenname, String nickname) 
        throws TokenException, EBaseException, NoSuchTokenException,
            NotInitializedException, CertificateException,
            CertificateEncodingException, EBaseException {
 
        X509Certificate cert = getCertificate(tokenname, nickname);
        X509CertImpl impl = new X509CertImpl(cert.getEncoded());

        return impl.getSubjectDN().getName();
    }

    public static X509CertImpl signCert(PrivateKey privateKey, X509CertInfo certInfo,
        SignatureAlgorithm sigAlg) 
        throws NoSuchTokenException, EBaseException, NotInitializedException {
        try {
            CertificateAlgorithmId sId = (CertificateAlgorithmId)
                certInfo.get(X509CertInfo.ALGORITHM_ID);
            AlgorithmId sigAlgId =
                (AlgorithmId) sId.get(CertificateAlgorithmId.ALGORITHM);

            org.mozilla.jss.crypto.PrivateKey priKey = 
                (org.mozilla.jss.crypto.PrivateKey) privateKey;
            CryptoToken token = priKey.getOwningToken();

            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream out = new DerOutputStream();

            certInfo.encode(tmp);

            Signature signer = token.getSignatureContext(sigAlg);

            signer.initSign(priKey);
            signer.update(tmp.toByteArray());
            byte signed[] = signer.sign();

            sigAlgId.encode(tmp);
            tmp.putBitString(signed);

            out.write(DerValue.tag_Sequence, tmp);

            X509CertImpl signedCert = new X509CertImpl(out.toByteArray());

            return signedCert;
        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_SIGNED_FAILED", e.toString()));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", e.toString()));
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR_1", e.toString()));
        } catch (SignatureException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_SIGNED_FAILED", e.toString()));
        } catch (InvalidKeyException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEY_1", e.toString()));
        } catch (CertificateException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }
    } 

    public static SignatureAlgorithm getSigningAlgorithm(String keyType) {
        SignatureAlgorithm sAlg = null;

        if (keyType.equals("RSA"))
            sAlg = SignatureAlgorithm.RSASignatureWithMD5Digest;
        else
            sAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;

        return sAlg;
    }

    public static SignatureAlgorithm getSigningAlgorithm(String keyType, String hashtype) {
        SignatureAlgorithm sAlg = null;

        if (keyType.equals("RSA")) {
            if (hashtype.equals("MD2"))
                sAlg = SignatureAlgorithm.RSASignatureWithMD2Digest;
            else if (hashtype.equals("MD5"))
                sAlg = SignatureAlgorithm.RSASignatureWithMD5Digest;
            else if (hashtype.equals("SHA1"))
                sAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
            else if (hashtype.equals("SHA256"))
                sAlg = SignatureAlgorithm.RSASignatureWithSHA256Digest;
            else if (hashtype.equals("SHA512"))
                sAlg = SignatureAlgorithm.RSASignatureWithSHA512Digest;
        } else {
            sAlg = SignatureAlgorithm.DSASignatureWithSHA1Digest;
        }

        return sAlg;
    }

    public static AlgorithmId getAlgorithmId(String algname, IConfigStore store)
        throws EBaseException {
        try {
            
            if (algname.equals("DSA")) {
                byte[] p = store.getByteArray("ca.dsaP", null);
                byte[] q = store.getByteArray("ca.dsaQ", null);
                byte[] g = store.getByteArray("ca.dsaG", null);

                if (p != null && q != null && g != null) {
                    BigInteger P = new BigInteger(p);
                    BigInteger Q = new BigInteger(q);
                    BigInteger G = new BigInteger(g);

                    return new AlgIdDSA(P, Q, G);
                }
            }
            return AlgorithmId.getAlgorithmId(algname);
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED"));
        }
    }

    public static X509Certificate getCertificate(String tokenname,
        String nickname) throws NotInitializedException, NoSuchTokenException,
            EBaseException, TokenException {
        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = null; 

        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            token = manager.getInternalKeyStorageToken();
        } else {
            token = manager.getTokenByName(tokenname);
        }
        StringBuffer certname = new StringBuffer();

        if (!token.equals(manager.getInternalKeyStorageToken())) {
            certname.append(tokenname);
            certname.append(":");
        }
        certname.append(nickname);
        try {
            return manager.findCertByNickname(certname.toString());
        } catch (ObjectNotFoundException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CA_SIGNINGCERT_NOT_FOUND"));
        }
    }

    public static KeyPair getKeyPair(String tokenname, String nickname) 
        throws NotInitializedException, NoSuchTokenException, TokenException,
            ObjectNotFoundException, EBaseException {
        X509Certificate cert = getCertificate(tokenname, nickname);
        PrivateKey priKey =
            CryptoManager.getInstance().findPrivKeyByCert(cert);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, priKey);
    }

    public static PQGParams getPQG(int keysize) {
        try {
            return PQGParams.generate(keysize);
        } catch (Exception e) {
            return null;
        }
    }

    public static PQGParams getCAPQG(int keysize, IConfigStore store) 
        throws EBaseException {
        if (store != null) {
            try {
                int pqgKeySize = store.getInteger("ca.dsaPQG.keyLength", 0);

                if ((pqgKeySize > 0) && (pqgKeySize == keysize)) {
                    byte[] p = store.getByteArray("ca.dsaP", null);
                    byte[] q = store.getByteArray("ca.dsaQ", null);
                    byte[] g = store.getByteArray("ca.dsaG", null);
                    byte[] seed = store.getByteArray("ca.dsaSeed", null);
                    byte[] H = store.getByteArray("ca.dsaH", null);
                    int counter = store.getInteger("ca.dsaCounter", 0);

                    if (p != null && q != null && g != null) {
                        BigInteger P = new BigInteger(p);
                        BigInteger Q = new BigInteger(q);
                        BigInteger G = new BigInteger(g);
                        BigInteger pqgSeed = new BigInteger(seed);
                        BigInteger pqgH = new BigInteger(H);

                        return new PQGParams(P, Q, G, pqgSeed, counter, pqgH);
                    }
                }
                PQGParams pqg = PQGParams.generate(keysize);

                store.putInteger("ca.dsaPQG.keyLength", keysize);
                store.putString("ca.dsaP", KeyCertUtil.base64Encode(
                        pqg.getP().toByteArray()));
                store.putString("ca.dsaQ", KeyCertUtil.base64Encode(
                        pqg.getQ().toByteArray()));
                store.putString("ca.dsaG", KeyCertUtil.base64Encode(
                        pqg.getG().toByteArray()));
                store.putString("ca.dsaSeed", KeyCertUtil.base64Encode(
                        pqg.getSeed().toByteArray()));
                store.putInteger("ca.dsaCounter", pqg.getCounter());
                store.putString("ca.dsaH", KeyCertUtil.base64Encode(
                        pqg.getH().toByteArray()));
                store.putString("ca.DSSParms", 
                    KeyCertUtil.base64Encode(
                        KeyCertUtil.makeDSSParms(pqg.getP(), pqg.getQ(), pqg.getG())));
                store.commit(false);
                return pqg;
            } catch (IOException ee) {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
            } catch (EBaseException ee) {
                throw ee;
            } catch (PQGParamGenException ee) {
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
            }
        }
        return null;
    }

    public static KeyPair generateKeyPair(CryptoToken token,
        KeyPairAlgorithm kpAlg, int keySize, PQGParams pqg) 
        throws NoSuchAlgorithmException, TokenException, InvalidAlgorithmParameterException,
            InvalidParameterException, PQGParamGenException {

        KeyPairGenerator kpGen = token.getKeyPairGenerator(kpAlg);
 
        if (kpAlg == KeyPairAlgorithm.DSA) {
            if (pqg == null) {
                kpGen.initialize(keySize);
            } else {
                kpGen.initialize(pqg);
            }
        } else {
            kpGen.initialize(keySize);
        }

        if (pqg == null) {
            return kpGen.genKeyPair();
        } else {
            // DSA
            KeyPair kp = null;

            do {
                // 602548 NSS bug - to overcome it, we use isBadDSAKeyPair
                kp = kpGen.genKeyPair();
            }
            while (isBadDSAKeyPair(kp)); 
            return kp;
        }
    }

    /**
     * Test for a DSA key pair that will trigger a bug in NSS.
     * The problem occurs when the first byte of the key is 0. This
     * happens when the value otherwise would have been negative, and a
     * zero byte is prepended to force it to be positive.
     * This is blackflag bug 602548.
     */
    public static boolean isBadDSAKeyPair(KeyPair pair) {
        try {
            byte[] pubkBytes = pair.getPublic().getEncoded();
            SEQUENCE.Template outerSeq = new SEQUENCE.Template();

            outerSeq.addElement(new ANY.Template()); // algid
            outerSeq.addElement(new BIT_STRING.Template()); // key value
            SEQUENCE seq = (SEQUENCE) ASN1Util.decode(outerSeq, pubkBytes);

            BIT_STRING bs = (BIT_STRING) seq.elementAt(1);
            byte[] bits = bs.getBits();
            ByteArrayInputStream bitstream = new ByteArrayInputStream(bs.getBits());
            ASN1Header wrapper = new ASN1Header(bitstream);
            byte[] valBytes = new byte[ (int) wrapper.getContentLength() ];

            ASN1Util.readFully(valBytes, bitstream);

            boolean isBroken = (valBytes[0] == 0);

            return isBroken;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static KeyPair generateKeyPair(String tokenName, String alg,
        int keySize, PQGParams pqg) throws EBaseException {

        CryptoToken token = null;

        if (tokenName.equalsIgnoreCase(Constants.PR_INTERNAL_TOKEN))
            tokenName = Constants.PR_INTERNAL_TOKEN_NAME;

        try {
            if (tokenName.equalsIgnoreCase(Constants.PR_INTERNAL_TOKEN)) {
                token = CryptoManager.getInstance().getInternalKeyStorageToken();
            } else {
                token = CryptoManager.getInstance().getTokenByName(tokenName);
            }
        } catch (NoSuchTokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_NOT_FOUND", tokenName));
        } catch (NotInitializedException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CRYPTOMANAGER_UNINITIALIZED"));
        }

        KeyPairAlgorithm kpAlg = null;

        if (alg.equals("RSA"))
            kpAlg = KeyPairAlgorithm.RSA;
        else
            kpAlg = KeyPairAlgorithm.DSA;

        try {
            KeyPair kp = generateKeyPair(token, kpAlg, keySize, pqg);

            return kp;
        } catch (InvalidParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_KEYSIZE_PARAMS",
                        "" + keySize));
        } catch (PQGParamGenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PQG_GEN_FAILED"));
        } catch (NoSuchAlgorithmException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED",
                        kpAlg.toString()));
        } catch (TokenException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_TOKEN_ERROR_1", e.toString()));
        } catch (InvalidAlgorithmParameterException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_ALG_NOT_SUPPORTED", "DSA"));
        }
    }

    public static PKCS10 getCertRequest(String subjectName, KeyPair keyPair) 
        throws NoSuchAlgorithmException, NoSuchProviderException, 
            InvalidKeyException, IOException, CertificateException,
            SignatureException {
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);
        String alg;

        if (pubk instanceof RSAPublicKey) {
            alg = "MD5/RSA";
        } else {
            alg = "DSA";
        }
        java.security.Signature sig =
            java.security.Signature.getInstance(alg, "Mozilla-JSS");

        sig.initSign(keyPair.getPrivate());

        PKCS10 pkcs10 = new PKCS10(key);

        X500Name name = new X500Name(subjectName);
        X500Signer signer = new X500Signer(sig, name);

        pkcs10.encodeAndSign(signer);

        return pkcs10;
    }

    public static PKCS10 getCertRequest(String subjectName, KeyPair
        keyPair, Extensions
        exts) 
        throws NoSuchAlgorithmException, NoSuchProviderException, 
            InvalidKeyException, IOException, CertificateException,
            SignatureException {
        PublicKey pubk = keyPair.getPublic();
        X509Key key = convertPublicKeyToX509Key(pubk);
        String alg;

        if (pubk instanceof RSAPublicKey) {
            alg = "MD5/RSA";
        } else {
            alg = "DSA";
        }
        java.security.Signature sig =
            java.security.Signature.getInstance(alg, "Mozilla-JSS");

        sig.initSign(keyPair.getPrivate());

        PKCS10 pkcs10 = null;

        if (exts != null) {
            PKCS10Attribute attr = new
                PKCS10Attribute(PKCS9Attribute.EXTENSION_REQUEST_OID,
                    (CertAttrSet) exts);
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

    public static X509Key convertPublicKeyToX509Key(PublicKey pubk) 
        throws InvalidKeyException {

        X509Key xKey;

        if (pubk instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) pubk;

            // REMOVED constructors from parameters by MLH on 1/9/99
            xKey = new netscape.security.provider.RSAPublicKey(
                        new BigInt(rsaKey.getModulus()),
                        new BigInt(rsaKey.getPublicExponent()));
        } else {
            DSAPublicKey dsaKey = (DSAPublicKey) pubk;
            DSAParams params = dsaKey.getParams();

            xKey = new netscape.security.provider.DSAPublicKey(
                        dsaKey.getY(),
                        params.getP(),
                        params.getQ(),
                        params.getG());
        }
        return xKey;
    }

    public static X509Certificate
    importCert(X509CertImpl signedCert, String nickname,
        String certType) throws NotInitializedException, TokenException,
            CertificateEncodingException, UserCertConflictException,
            NicknameConflictException, NoSuchItemOnTokenException, CertificateException {
      
        return importCert(signedCert.getEncoded(), nickname, certType);
    }

    public static X509Certificate
    importCert(String b64E, String nickname, String certType)
        throws NotInitializedException, TokenException,
            CertificateEncodingException, UserCertConflictException,
            NicknameConflictException, NoSuchItemOnTokenException, CertificateException {
 
        byte b[] = b64E.getBytes();
        X509Certificate cert = getInternalCertificate(b, nickname, certType);
 
        if (cert instanceof InternalCertificate) {
            setTrust(certType, (InternalCertificate) cert);
        }
        return cert;
    }

    public static X509Certificate
    importCert(byte[] b, String nickname, String certType) 
        throws NotInitializedException, TokenException, 
            CertificateEncodingException, UserCertConflictException, 
            NicknameConflictException, NoSuchItemOnTokenException, CertificateException {

        X509Certificate cert = getInternalCertificate(b, nickname, certType);

        if (cert instanceof InternalCertificate) {
            setTrust(certType, (InternalCertificate) cert);
        }
        return cert;
    }

    public static X509Certificate getInternalCertificate(byte[] b, String nickname, String certType) 
        throws NotInitializedException, TokenException, CertificateEncodingException,
            UserCertConflictException, NicknameConflictException, NoSuchItemOnTokenException,
            CertificateException {
        X509Certificate cert = null;

        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            cert = CryptoManager.getInstance().importUserCACertPackage(b,
                        nickname);
        } else if (certType.equals(Constants.PR_RA_SIGNING_CERT) ||
            certType.equals(Constants.PR_KRA_TRANSPORT_CERT) ||
            certType.equals(Constants.PR_OCSP_SIGNING_CERT) ||
            certType.equals(Constants.PR_SERVER_CERT) ||
            certType.equals(Constants.PR_SERVER_CERT_RADM) ||
            certType.equals(Constants.PR_OTHER_CERT) ||
            certType.equals(Constants.PR_SUBSYSTEM_CERT)) {
            cert = CryptoManager.getInstance().importCertPackage(b,
                        nickname);
        } else if (certType.equals(Constants.PR_SERVER_CERT_CHAIN)) {
            cert = CryptoManager.getInstance().importCACertPackage(b);
        } else if (certType.equals(Constants.PR_TRUSTED_CA_CERT)) {
            cert = CryptoManager.getInstance().importCACertPackage(b);
            X509Certificate[] certchain = CryptoManager.getInstance().buildCertificateChain(cert);

            if (certchain != null) {
                cert = certchain[certchain.length - 1];
            }
        }
        return cert;   
    }

    public static void setTrust(String certType, InternalCertificate inCert) {
        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            int flag = InternalCertificate.VALID_CA |
                InternalCertificate.TRUSTED_CA |
                InternalCertificate.USER |
                InternalCertificate.TRUSTED_CLIENT_CA;

            inCert.setSSLTrust(flag);
            inCert.setObjectSigningTrust(flag);
            inCert.setEmailTrust(flag);
        } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
            int flag = InternalCertificate.USER | InternalCertificate.VALID_CA;

            inCert.setSSLTrust(flag);
            inCert.setObjectSigningTrust(flag);
            inCert.setEmailTrust(flag); 
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            int flag = InternalCertificate.USER | InternalCertificate.VALID_CA;

            inCert.setSSLTrust(flag);
            inCert.setObjectSigningTrust(flag);
            inCert.setEmailTrust(flag); 
        } else if (certType.equals(Constants.PR_SERVER_CERT) ||
          certType.equals(Constants.PR_SUBSYSTEM_CERT)) {
            int flag = InternalCertificate.USER | InternalCertificate.VALID_CA;

            inCert.setSSLTrust(flag);
            inCert.setObjectSigningTrust(flag);
            inCert.setEmailTrust(flag); 
        } else if (certType.equals(Constants.PR_TRUSTED_CA_CERT)) {
            inCert.setSSLTrust(InternalCertificate.TRUSTED_CA | InternalCertificate.TRUSTED_CLIENT_CA |
                InternalCertificate.VALID_CA);
            //inCert.setEmailTrust(InternalCertificate.TRUSTED_CA);

            // cannot set this bit. If set, then the cert will not appear when you called getCACerts().
            //inCert.setObjectSigningTrust(InternalCertificate.TRUSTED_CA);
        }
    }

    public static byte[] convertB64EToByteArray(String b64E)
        throws CertificateException, IOException {
        String str = CertUtils.stripCertBrackets(b64E);
        byte bCert[] = (byte[]) (com.netscape.osutil.OSUtil.AtoB(str));

        /*
         java.security.cert.X509Certificate cert = 
         java.security.cert.X509Certificate.getInstance(bCert);
         return cert;
         */
        return bCert;
    }

    /**
     * ASN.1 structure:
     *  0 30  142: SEQUENCE {
     *  3 30   69:   SEQUENCE {
     *  5 06    3:     OBJECT IDENTIFIER issuerAltName (2 5 29 18)
     * 10 04   62:     OCTET STRING
     *           :       30 3C 82 01 61 82 01 61 A4 10 30 0E 31 0C 30 0A
     *           :       06 03 55 04 03 13 03 64 73 61 87 04 01 01 01 01
     *           :       86 01 61 81 14 74 68 6F 6D 61 73 6B 40 6E 65 74
     *           :       73 63 61 70 65 2E 63 6F 6D 88 03 29 01 01
     *           :     }
     * 74 30   69:   SEQUENCE {
     * 76 06    3:     OBJECT IDENTIFIER subjectAltName (2 5 29 17)
     * 81 04   62:     OCTET STRING
     *           :       30 3C 82 01 61 82 01 61 A4 10 30 0E 31 0C 30 0A
     *           :       06 03 55 04 03 13 03 64 73 61 87 04 01 01 01 01
     *           :       86 01 61 81 14 74 68 6F 6D 61 73 6B 40 6E 65 74
     *           :       73 63 61 70 65 2E 63 6F 6D 88 03 29 01 01
     *           :     }
     *           :   }
     * Uses the following to test with configuration wizard:
     * MIGOMEUGA1UdEQQ+MDyCAWGCAWGkEDAOMQwwCgYDVQQDEwNkc2GHBAEBAQGGAWGB
     * FHRob21hc2tAbmV0c2NhcGUuY29tiAMpAQEwRQYDVR0SBD4wPIIBYYIBYaQQMA4x
     * DDAKBgNVBAMTA2RzYYcEAQEBAYYBYYEUdGhvbWFza0BuZXRzY2FwZS5jb22IAykB
     * AQ== 
     */
    public static void setDERExtension(
        CertificateExtensions ext, KeyCertData properties) 
        throws IOException {

        String b64E = properties.getDerExtension();

        if (b64E != null) {
            byte[] b = (byte[]) (com.netscape.osutil.OSUtil.AtoB(b64E));

            // this b can be "Extension" Or "SEQUENCE OF Extension"
            try {
                DerValue b_der = new DerValue(b);

                while (b_der.data.available() != 0) {
                    Extension de = new Extension(b_der.data.getDerValue());

                    ext.set(de.getExtensionId().toString(), de);
                }
            } catch (IOException e) {
                Extension de = new Extension(new DerValue(b));

                ext.set(de.getExtensionId().toString(), de);
            }
        }
    }

    public static void setBasicConstraintsExtension(
        CertificateExtensions ext, KeyCertData properties) 
        throws IOException {
        String isCA = properties.isCA();
        String certLen = properties.getCertLen();

        if (isCA == null)
            return; // isCA is not optional
        if (isCA.equals("null"))
            return; // no BasicConstraints requested
        if ((isCA == null) && (certLen == null))
            return;
        int len = 0;
        boolean bool = false;

        if ((certLen == null) || (certLen.equals("")))
            len = 0;
        else
            len = Integer.parseInt(certLen);

        if ((isCA == null) || (isCA.equals("")) || 
            (isCA.equals(Constants.FALSE)))
            bool = false;
        else
            bool = true;
            
        BasicConstraintsExtension basic = new BasicConstraintsExtension(
                bool, len);

        ext.set(BasicConstraintsExtension.NAME, basic);
    }

    public static void setExtendedKeyUsageExtension(
        CertificateExtensions ext, KeyCertData properties) throws IOException,
            CertificateException {
        ExtendedKeyUsageExtension ns = new ExtendedKeyUsageExtension();
        boolean anyExt = false;
        
        String sslClient = properties.getSSLClientBit();
        
        if ((sslClient != null) && (sslClient.equals(Constants.TRUE))) {
            ns.addOID(new ObjectIdentifier("1.3.6.1.5.5.7.3.2"));
            anyExt = true;
        }   

        String sslServer = properties.getSSLServerBit();

        if ((sslServer != null) && (sslServer.equals(Constants.TRUE))) {
            ns.addOID(new ObjectIdentifier("1.3.6.1.5.5.7.3.1"));
            anyExt = true;
        }

        String sslMail = properties.getSSLMailBit();

        if ((sslMail != null) && (sslMail.equals(Constants.TRUE))) {
            ns.addOID(new ObjectIdentifier("1.3.6.1.5.5.7.3.4"));
            anyExt = true;
        }

        String objectSigning = properties.getObjectSigningBit();

        if ((objectSigning != null) && (objectSigning.equals(Constants.TRUE))) {
            ns.addOID(new ObjectIdentifier("1.3.6.1.5.5.7.3.3"));
            anyExt = true;
        }

        String timestamping = properties.getTimeStampingBit();
        if ((timestamping != null) && (timestamping.equals(Constants.TRUE))) {
            ns.addOID(new ObjectIdentifier("1.3.6.1.5.5.7.3.8"));
            anyExt = true;
        }

        String ocspSigning = properties.getOCSPSigning();

        if ((ocspSigning != null) && (ocspSigning.equals(Constants.TRUE))) {
            ns.addOID(new ObjectIdentifier("1.3.6.1.5.5.7.3.9"));
            anyExt = true;
        }

        if (anyExt)
            ext.set(ExtendedKeyUsageExtension.NAME, ns);
    }

    public static void setNetscapeCertificateExtension(
        CertificateExtensions ext, KeyCertData properties) throws IOException,
            CertificateException {

        NSCertTypeExtension ns = new NSCertTypeExtension();
        boolean anyExt = false;

        String sslClient = properties.getSSLClientBit();

        if ((sslClient != null) && (sslClient.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.SSL_CLIENT, new Boolean(true));
            anyExt = true;
        }

        String sslServer = properties.getSSLServerBit();

        if ((sslServer != null) && (sslServer.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.SSL_SERVER, new Boolean(true));
            anyExt = true;
        }

        String sslMail = properties.getSSLMailBit();

        if ((sslMail != null) && (sslMail.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.EMAIL, new Boolean(true));
            anyExt = true;
        }

        String sslCA = properties.getSSLCABit();

        if ((sslCA != null) && (sslCA.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.SSL_CA, new Boolean(true));
            anyExt = true;
        }

        String objectSigning = properties.getObjectSigningBit();

        if ((objectSigning != null) && (objectSigning.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.OBJECT_SIGNING, new Boolean(true));
            anyExt = true;
        }

        String mailCA = properties.getMailCABit();

        if ((mailCA != null) && (mailCA.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.EMAIL_CA, new Boolean(true));
            anyExt = true;
        }

        String objectSigningCA = properties.getObjectSigningCABit();

        if ((objectSigningCA != null) && (objectSigningCA.equals(Constants.TRUE))) {
            ns.set(NSCertTypeExtension.OBJECT_SIGNING_CA, new Boolean(true));
            anyExt = true;
        }
        if (anyExt)
            ext.set(NSCertTypeExtension.NAME, ns);
    }

    public static void setOCSPNoCheck(KeyPair keypair, 
        CertificateExtensions ext, KeyCertData properties) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException {
        String noCheck = properties.getOCSPNoCheck();

        if ((noCheck != null) && (noCheck.equals(Constants.TRUE))) {
            OCSPNoCheckExtension noCheckExt = 
                new OCSPNoCheckExtension();

            ext.set(OCSPNoCheckExtension.NAME, noCheckExt);
        }
    }

    public static void setOCSPSigning(KeyPair keypair, 
        CertificateExtensions ext, KeyCertData properties) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException {
        String signing = properties.getOCSPSigning();

        if ((signing != null) && (signing.equals(Constants.TRUE))) { 
            Vector oidSet = new Vector(); 
            oidSet.addElement(
              ObjectIdentifier.getObjectIdentifier(
                ExtendedKeyUsageExtension.OID_OCSPSigning));
            ExtendedKeyUsageExtension ocspExt = 
                new ExtendedKeyUsageExtension(false, oidSet);
            ext.set(ExtendedKeyUsageExtension.NAME, ocspExt);
        }
    }

    public static void setAuthInfoAccess(KeyPair keypair, 
        CertificateExtensions ext, KeyCertData properties) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException {
        String aia = properties.getAIA();

        if ((aia != null) && (aia.equals(Constants.TRUE))) {
            String hostname = CMS.getEENonSSLHost();
            String port = CMS.getEENonSSLPort();
            AuthInfoAccessExtension aiaExt = new AuthInfoAccessExtension(false);
            if (hostname != null && port != null) {
                String location = "http://"+hostname+":"+port+"/ca/ocsp";
                GeneralName ocspName = new GeneralName(new URIName(location));
                aiaExt.addAccessDescription(AuthInfoAccessExtension.METHOD_OCSP, ocspName);
            }

            ext.set(AuthInfoAccessExtension.NAME, aiaExt);
        }
    }

    public static void setAuthorityKeyIdentifier(KeyPair keypair, 
        CertificateExtensions ext, KeyCertData properties) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException {
        String aki = properties.getAKI();

        if ((aki != null) && (aki.equals(Constants.TRUE))) {
            KeyIdentifier id = createKeyIdentifier(keypair);
            AuthorityKeyIdentifierExtension akiExt = 
                new AuthorityKeyIdentifierExtension(id, null, null);

            ext.set(AuthorityKeyIdentifierExtension.NAME, akiExt);
        }
    }

    public static void setSubjectKeyIdentifier(KeyPair keypair, 
        CertificateExtensions ext,
        KeyCertData properties) throws IOException, NoSuchAlgorithmException, 
            InvalidKeyException {
        String ski = properties.getSKI();

        if ((ski != null) && (ski.equals(Constants.TRUE))) {
            KeyIdentifier id = createKeyIdentifier(keypair);
            SubjectKeyIdentifierExtension skiExt =
                new SubjectKeyIdentifierExtension(id.getIdentifier());

            ext.set(SubjectKeyIdentifierExtension.NAME, skiExt);
        }
    }

    public static void setKeyUsageExtension(CertificateExtensions ext,
        KeyUsageExtension keyUsage) throws IOException {
        ext.set(KeyUsageExtension.NAME, keyUsage);
    }

    public static KeyIdentifier createKeyIdentifier(KeyPair keypair) 
        throws NoSuchAlgorithmException, InvalidKeyException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        X509Key subjectKeyInfo = convertPublicKeyToX509Key(
                keypair.getPublic());

        //md.update(subjectKeyInfo.getEncoded());
        md.update(subjectKeyInfo.getKey());
        return new KeyIdentifier(md.digest());
    }

    public static BigInteger getSerialNumber(LDAPConnection conn, String baseDN) 
        throws LDAPException {
        String dn = "ou=certificateRepository,ou=ca," + baseDN;
        BigInteger serialno = null;
        LDAPEntry entry = conn.read(dn);
        String serialnoStr = (String) entry.getAttribute(
                "serialno").getStringValues().nextElement();

        serialno = BigIntegerMapper.BigIntegerFromDB(serialnoStr);
        LDAPAttribute attr = new LDAPAttribute("serialno");

        attr.addValue(BigIntegerMapper.BigIntegerToDB(
                serialno.add(new BigInteger("1"))));
        LDAPModification mod = new LDAPModification(
                LDAPModification.REPLACE, attr);

        conn.modify(dn, mod);

        return serialno;
    }

    public static void setSerialNumber(LDAPConnection conn, 
        String baseDN, BigInteger serial) 
        throws LDAPException {
        String dn = "ou=certificateRepository,ou=ca," + baseDN;
        LDAPAttribute attr = new LDAPAttribute("serialno");

        // the serial number should already be set
        attr.addValue(BigIntegerMapper.BigIntegerToDB(
                serial));
        LDAPModification mod = new LDAPModification(
                LDAPModification.REPLACE, attr);

        conn.modify(dn, mod);

    }

    public static void addCertToDB(LDAPConnection conn, String dn, X509CertImpl cert)
        throws LDAPException, EBaseException {
        BigInteger serialno = cert.getSerialNumber();
        X509CertImplMapper mapper = new X509CertImplMapper();
        LDAPAttributeSet attrs = new LDAPAttributeSet();

        mapper.mapObjectToLDAPAttributeSet(null, null,
            cert, attrs);
        attrs.add(new LDAPAttribute("objectclass", "top"));
        attrs.add(new LDAPAttribute("objectclass",
                "certificateRecord"));
        attrs.add(new LDAPAttribute("serialno",
                BigIntegerMapper.BigIntegerToDB(
                    serialno)));
        attrs.add(new LDAPAttribute("dateOfCreate",
                DateMapper.dateToDB((CMS.getCurrentDate()))));
        attrs.add(new LDAPAttribute("dateOfModify",
                DateMapper.dateToDB((CMS.getCurrentDate()))));
        attrs.add(new LDAPAttribute("certStatus",
                "VALID"));
        attrs.add(new LDAPAttribute("autoRenew",
                "ENABLED"));
        attrs.add(new LDAPAttribute("issuedBy",
                "installation"));
        LDAPEntry entry = new LDAPEntry("cn=" + serialno.toString() + "," + dn, attrs);

        conn.add(entry);
    }

    public static CertificateExtensions getExtensions(String tokenname, String nickname) 
        throws NotInitializedException, TokenException, ObjectNotFoundException, 
            IOException, CertificateException {
        String fullnickname = nickname;

        if (!tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) 
            fullnickname = tokenname + ":" + nickname;
        CryptoManager manager = CryptoManager.getInstance();
        X509Certificate cert = manager.findCertByNickname(fullnickname);
        X509CertImpl impl = new X509CertImpl(cert.getEncoded());
        X509CertInfo info = (X509CertInfo) impl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

        return (CertificateExtensions) info.get(X509CertInfo.EXTENSIONS);
    }
}
