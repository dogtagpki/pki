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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package netscape.security.pkcs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;
import org.mozilla.jss.util.Password;

import netscape.ldap.LDAPDN;
import netscape.security.x509.X509CertImpl;

public class PKCS12Util {

    private static Logger logger = Logger.getLogger(PKCS12Util.class.getName());

    PFX pfx;
    boolean trustFlagsEnabled = true;

    public static class PKCS12KeyInfo {
        public EncryptedPrivateKeyInfo encPrivateKeyInfo;
        public PrivateKeyInfo privateKeyInfo;
        public String subjectDN;
    }

    public static class PKCS12CertInfo {
        public X509CertImpl cert;
        public String nickname;
        public String trustFlags;
    }

    public boolean isTrustFlagsEnabled() {
        return trustFlagsEnabled;
    }

    public void setTrustFlagsEnabled(boolean trustFlagsEnabled) {
        this.trustFlagsEnabled = trustFlagsEnabled;
    }

    public String getTrustFlags(X509Certificate cert) {

        InternalCertificate icert = (InternalCertificate) cert;

        StringBuilder sb = new StringBuilder();

        sb.append(PKCS12.encodeFlags(icert.getSSLTrust()));
        sb.append(",");
        sb.append(PKCS12.encodeFlags(icert.getEmailTrust()));
        sb.append(",");
        sb.append(PKCS12.encodeFlags(icert.getObjectSigningTrust()));

        return sb.toString();
    }

    public void setTrustFlags(X509Certificate cert, String trustFlags) throws Exception {

        InternalCertificate icert = (InternalCertificate) cert;

        String[] flags = trustFlags.split(",");
        if (flags.length < 3) throw new Exception("Invalid trust flags: " + trustFlags);

        icert.setSSLTrust(PKCS12.decodeFlags(flags[0]));
        icert.setEmailTrust(PKCS12.decodeFlags(flags[1]));
        icert.setObjectSigningTrust(PKCS12.decodeFlags(flags[2]));
    }

    byte[] getEncodedKey(PrivateKey privateKey) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
        SymmetricKey sk = kg.generate();

        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        byte[] iv = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec param = new IVParameterSpec(iv);
        wrapper.initWrap(sk, param);
        byte[] enckey = wrapper.wrap(privateKey);

        Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        c.initDecrypt(sk, param);
        return c.doFinal(enckey);
    }

    public void addKeyBag(PrivateKey privateKey, X509Certificate x509cert,
            Password pass, byte[] localKeyID, SEQUENCE safeContents) throws Exception {

        logger.fine("Creating key bag for " + x509cert.getSubjectDN());

        PasswordConverter passConverter = new PasswordConverter();
        byte salt[] = { 0x01, 0x01, 0x01, 0x01 };
        byte[] priData = getEncodedKey(privateKey);

        PrivateKeyInfo pki = (PrivateKeyInfo)
                ASN1Util.decode(PrivateKeyInfo.getTemplate(), priData);

        ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
                PBEAlgorithm.PBE_SHA1_DES3_CBC,
                pass, salt, 1, passConverter, pki);

        SET keyAttrs = createKeyBagAttrs(
                x509cert.getSubjectDN().toString(), localKeyID);

        SafeBag keyBag = new SafeBag(SafeBag.PKCS8_SHROUDED_KEY_BAG,
                key, keyAttrs);

        safeContents.addElement(keyBag);
    }

    public byte[] addCertBag(X509Certificate x509cert, String nickname,
            SEQUENCE safeContents) throws Exception {

        logger.fine("Creating cert bag for " + nickname);

        ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
        byte[] localKeyID = createLocalKeyID(x509cert);

        String trustFlags = null;
        if (trustFlagsEnabled) {
            trustFlags = getTrustFlags(x509cert);
            logger.fine("Trust flags: " + trustFlags);
        }

        SET certAttrs = createCertBagAttrs(nickname, localKeyID, trustFlags);

        SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
                new CertBag(CertBag.X509_CERT_TYPE, cert), certAttrs);

        safeContents.addElement(certBag);

        return localKeyID;
    }

    byte[] createLocalKeyID(X509Certificate cert) throws Exception {

        // SHA1 hash of the X509Cert DER encoding
        byte[] certDer = cert.getEncoded();

        MessageDigest md = MessageDigest.getInstance("SHA");

        md.update(certDer);
        return md.digest();
    }

    SET createKeyBagAttrs(String subjectDN, byte localKeyID[])
            throws Exception {

        SET attrs = new SET();

        SEQUENCE subjectAttr = new SEQUENCE();
        subjectAttr.addElement(SafeBag.FRIENDLY_NAME);

        SET subjectSet = new SET();
        subjectSet.addElement(new BMPString(subjectDN));
        subjectAttr.addElement(subjectSet);

        attrs.addElement(subjectAttr);

        SEQUENCE localKeyAttr = new SEQUENCE();
        localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);

        SET localKeySet = new SET();
        localKeySet.addElement(new OCTET_STRING(localKeyID));
        localKeyAttr.addElement(localKeySet);

        attrs.addElement(localKeyAttr);

        return attrs;
    }

    SET createCertBagAttrs(String nickname, byte localKeyID[], String trustFlags)
            throws Exception {

        SET attrs = new SET();

        SEQUENCE nicknameAttr = new SEQUENCE();
        nicknameAttr.addElement(SafeBag.FRIENDLY_NAME);

        SET nicknameSet = new SET();
        nicknameSet.addElement(new BMPString(nickname));
        nicknameAttr.addElement(nicknameSet);

        attrs.addElement(nicknameAttr);

        SEQUENCE localKeyAttr = new SEQUENCE();
        localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);

        SET localKeySet = new SET();
        localKeySet.addElement(new OCTET_STRING(localKeyID));
        localKeyAttr.addElement(localKeySet);

        attrs.addElement(localKeyAttr);

        if (trustFlags != null && trustFlagsEnabled) {
            SEQUENCE trustFlagsAttr = new SEQUENCE();
            trustFlagsAttr.addElement(PKCS12.CERT_TRUST_FLAGS_OID);

            SET trustFlagsSet = new SET();
            trustFlagsSet.addElement(new BMPString(trustFlags));
            trustFlagsAttr.addElement(trustFlagsSet);

            attrs.addElement(trustFlagsAttr);
        }

        return attrs;
    }

    public void loadFromNSS(Password password) throws Exception {

        logger.info("Loading data from NSS database");

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        SEQUENCE encSafeContents = new SEQUENCE();
        SEQUENCE safeContents = new SEQUENCE();

        logger.fine("Loading certificates");

        X509Certificate[] certs = store.getCertificates();

        for (X509Certificate cert : certs) {
            String nickname = cert.getNickname();

            try {
                PrivateKey prikey = cm.findPrivKeyByCert(cert);
                logger.fine("Found certificate " + nickname + " with private key");

                byte localKeyID[] = addCertBag(cert, nickname, safeContents);
                addKeyBag(prikey, cert, password, localKeyID, encSafeContents);

            } catch (ObjectNotFoundException e) {
                logger.fine("Found certificate " + nickname + " without private key");
                addCertBag(cert, nickname, safeContents);
            }
        }

        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(safeContents);
        authSafes.addSafeContents(encSafeContents);

        pfx = new PFX(authSafes);
    }

    public void storeIntoPKCS12(String filename, Password password) throws Exception {

        logger.info("Storing data into PKCS #12 file");

        pfx.computeMacData(password, null, 5);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        pfx.encode(bos);
        byte[] data = bos.toByteArray();

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }

    public void exportData(String filename, Password password) throws Exception {

        loadFromNSS(password);
        storeIntoPKCS12(filename, password);
    }

    public PKCS12KeyInfo getKeyInfo(SafeBag bag, Password password) throws Exception {

        // get private key info
        EncryptedPrivateKeyInfo encPrivateKeyInfo = (EncryptedPrivateKeyInfo) bag.getInterpretedBagContent();

        PrivateKeyInfo privateKeyInfo = null;
        if (password != null) {
            privateKeyInfo = encPrivateKeyInfo.decrypt(password, new PasswordConverter());
        }

        // find private key's subject DN
        SET bagAttrs = bag.getBagAttributes();
        String subjectDN = null;

        for (int i = 0; i < bagAttrs.size(); i++) {

            Attribute attr = (Attribute) bagAttrs.elementAt(i);
            OBJECT_IDENTIFIER oid = attr.getType();

            if (!oid.equals(SafeBag.FRIENDLY_NAME)) continue;

            SET values = attr.getValues();
            ANY value = (ANY) values.elementAt(0);

            ByteArrayInputStream bbis = new ByteArrayInputStream(value.getEncoded());
            BMPString sss = (BMPString) new BMPString.Template().decode(bbis);
            subjectDN = sss.toString();

            break;
        }

        logger.fine("Found private key " + subjectDN);

        PKCS12KeyInfo keyInfo = new PKCS12KeyInfo();
        keyInfo.encPrivateKeyInfo = encPrivateKeyInfo;
        keyInfo.privateKeyInfo = privateKeyInfo;
        keyInfo.subjectDN = subjectDN;

        return keyInfo;
    }

    public PKCS12KeyInfo getKeyInfo(SafeBag bag) throws Exception {
        return getKeyInfo(bag, null);
    }

    public PKCS12CertInfo getCertInfo(SafeBag bag) throws Exception {

        PKCS12CertInfo certInfo = new PKCS12CertInfo();

        CertBag certBag = (CertBag) bag.getInterpretedBagContent();

        OCTET_STRING certStr = (OCTET_STRING) certBag.getInterpretedCert();
        byte[] x509cert = certStr.toByteArray();

        certInfo.cert = new X509CertImpl(x509cert);
        logger.fine("Found certificate " + certInfo.cert.getSubjectDN());

        SET bagAttrs = bag.getBagAttributes();
        if (bagAttrs == null) return certInfo;

        for (int i = 0; i < bagAttrs.size(); i++) {

            Attribute attr = (Attribute) bagAttrs.elementAt(i);
            OBJECT_IDENTIFIER oid = attr.getType();

            if (oid.equals(SafeBag.FRIENDLY_NAME)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream is = new ByteArrayInputStream(value.getEncoded());
                BMPString nicknameStr = (BMPString) (new BMPString.Template()).decode(is);

                certInfo.nickname = nicknameStr.toString();
                logger.fine("Nickname: " + certInfo.nickname);

            } else if (oid.equals(PKCS12.CERT_TRUST_FLAGS_OID) && trustFlagsEnabled) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream is = new ByteArrayInputStream(value.getEncoded());
                BMPString trustFlagsStr = (BMPString) (new BMPString.Template()).decode(is);

                certInfo.trustFlags = trustFlagsStr.toString();
                logger.fine("Trust flags: " + certInfo.trustFlags);
            }
        }

        return certInfo;
    }

    public List<PKCS12KeyInfo> getKeyInfos(Password password) throws Exception {

        logger.fine("Getting private keys");

        List<PKCS12KeyInfo> keyInfos = new ArrayList<PKCS12KeyInfo>();
        AuthenticatedSafes safes = pfx.getAuthSafes();

        for (int i = 0; i < safes.getSize(); i++) {

            SEQUENCE contents = safes.getSafeContentsAt(null, i);

            for (int j = 0; j < contents.size(); j++) {

                SafeBag bag = (SafeBag) contents.elementAt(j);
                OBJECT_IDENTIFIER oid = bag.getBagType();

                if (!oid.equals(SafeBag.PKCS8_SHROUDED_KEY_BAG)) continue;

                PKCS12KeyInfo keyInfo = getKeyInfo(bag, password);
                keyInfos.add(keyInfo);
            }
        }

        return keyInfos;
    }

    public List<PKCS12KeyInfo> getKeyInfos() throws Exception {
        return getKeyInfos(null);
    }

    public List<PKCS12CertInfo> getCertInfos() throws Exception {

        logger.fine("Getting certificates");

        List<PKCS12CertInfo> certInfos = new ArrayList<PKCS12CertInfo>();
        AuthenticatedSafes safes = pfx.getAuthSafes();

        for (int i = 0; i < safes.getSize(); i++) {

            SEQUENCE contents = safes.getSafeContentsAt(null, i);

            for (int j = 0; j < contents.size(); j++) {

                SafeBag bag = (SafeBag) contents.elementAt(j);
                OBJECT_IDENTIFIER oid = bag.getBagType();

                if (!oid.equals(SafeBag.CERT_BAG)) continue;

                PKCS12CertInfo certInfo = getCertInfo(bag);
                certInfos.add(certInfo);
            }
        }

        return certInfos;
    }

    public void loadFromPKCS12(String filename) throws Exception {

        logger.info("Loading PKCS #12 file");

        Path path = Paths.get(filename);
        byte[] b = Files.readAllBytes(path);

        ByteArrayInputStream bis = new ByteArrayInputStream(b);

        pfx = (PFX) (new PFX.Template()).decode(bis);
    }

    public PrivateKey.Type getPrivateKeyType(PublicKey publicKey) {
        if (publicKey.getAlgorithm().equals("EC")) {
            return PrivateKey.Type.EC;
        }
        return PrivateKey.Type.RSA;
    }

    public X509CertImpl getCertBySubjectDN(String subjectDN, List<PKCS12CertInfo> certInfos)
            throws CertificateException {

        for (PKCS12CertInfo certInfo : certInfos) {
            X509CertImpl cert = certInfo.cert;
            Principal certSubjectDN = cert.getSubjectDN();
            if (LDAPDN.equals(certSubjectDN.toString(), subjectDN)) return cert;
        }

        return null;
    }

    public void importKey(
            PKCS12KeyInfo keyInfo,
            Password password,
            List<PKCS12CertInfo> certInfos) throws Exception {

        PrivateKeyInfo privateKeyInfo = keyInfo.privateKeyInfo;

        if (privateKeyInfo == null) {
            privateKeyInfo = keyInfo.encPrivateKeyInfo.decrypt(password, new PasswordConverter());
        }

        String subjectDN = keyInfo.subjectDN;

        logger.fine("Importing private key " + subjectDN);

        // encode private key
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        privateKeyInfo.encode(bos);
        byte[] privateKey = bos.toByteArray();

        X509CertImpl x509cert = getCertBySubjectDN(subjectDN, certInfos);
        if (x509cert == null) {
            logger.fine("Private key nas no certificate, ignore");
            return;
        }

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        X509Certificate cert = cm.importCACertPackage(x509cert.getEncoded());

        // get public key
        PublicKey publicKey = cert.getPublicKey();

        // delete the cert again
        try {
            store.deleteCert(cert);
        } catch (NoSuchItemOnTokenException e) {
            // this is OK
        }

        // encrypt private key
        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
        SymmetricKey sk = kg.generate();
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec param = new IVParameterSpec(iv);
        Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        c.initEncrypt(sk, param);
        byte[] encpkey = c.doFinal(privateKey);

        // unwrap private key to load into database
        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        wrapper.initUnwrap(sk, param);
        wrapper.unwrapPrivate(encpkey, getPrivateKeyType(publicKey), publicKey);
    }

    public void importKeys(
            List<PKCS12KeyInfo> keyInfos,
            Password password,
            List<PKCS12CertInfo> certInfos
        ) throws Exception {

        for (int i = 0; i < keyInfos.size(); i++) {
            PKCS12KeyInfo keyInfo = keyInfos.get(i);
            importKey(keyInfo, password, certInfos);
        }
    }

    public X509Certificate importCert(X509CertImpl cert, String nickname, String trustFlags) throws Exception {

        logger.fine("Importing certificate " + cert.getSubjectDN());

        CryptoManager cm = CryptoManager.getInstance();

        X509Certificate xcert;

        if (nickname == null) {
            xcert = cm.importCACertPackage(cert.getEncoded());

        } else {
            xcert = cm.importUserCACertPackage(cert.getEncoded(), nickname);
        }

        if (trustFlags != null && trustFlagsEnabled)
            setTrustFlags(xcert, trustFlags);

        return xcert;
    }

    public void importCerts(List<PKCS12CertInfo> certInfos) throws Exception {

        for (PKCS12CertInfo certInfo : certInfos) {
            importCert(certInfo.cert, certInfo.nickname, certInfo.trustFlags);
        }
    }

    public void verifyPassword(Password password) throws Exception {

        StringBuffer reason = new StringBuffer();
        boolean valid = pfx.verifyAuthSafes(password, reason);

        if (!valid) {
            throw new Exception(reason.toString());
        }
    }

    public void storeIntoNSS(Password password) throws Exception {

        logger.info("Storing data into NSS database");

        verifyPassword(password);

        List<PKCS12KeyInfo> keyInfos = getKeyInfos();
        List<PKCS12CertInfo> certInfos = getCertInfos();

        importKeys(keyInfos, password, certInfos);
        importCerts(certInfos);
    }

    public void importData(String filename, Password password) throws Exception {

        loadFromPKCS12(filename);
        storeIntoNSS(password);
    }
}
