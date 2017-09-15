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
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import netscape.ldap.LDAPDN;
import netscape.ldap.util.DN;
import netscape.security.x509.X509CertImpl;

public class PKCS12Util {

    private static Logger logger = LoggerFactory.getLogger(PKCS12Util.class);

    boolean trustFlagsEnabled = true;

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

        String[] flags = trustFlags.split(",", -1); // don't remove empty string
        if (flags.length < 3) throw new Exception("Invalid trust flags: " + trustFlags);

        icert.setSSLTrust(PKCS12.decodeFlags(flags[0]));
        icert.setEmailTrust(PKCS12.decodeFlags(flags[1]));
        icert.setObjectSigningTrust(PKCS12.decodeFlags(flags[2]));
    }

    /** Add a private key to the PKCS #12 object.
     *
     * The PKCS12KeyInfo object received comes about in two
     * different scenarios:
     *
     * - The private key could be in encrypted byte[] form (e.g.
     *   when we have merely loaded a PKCS #12 file for inspection
     *   or e.g. to delete a certificate and its associated key).
     *   In this case we simply re-use this encrypted private key
     *   info byte[].
     *
     * - The private key could be a be an NSS PrivateKey handle.  In
     *   this case we must export the PrivateKey from the token to
     *   obtain the EncryptedPrivateKeyInfo.
     *
     * The common final step is to add the encrypted private key
     * data to a "Shrouded Key Bag" to the PKCS #12 object.
     * Unencrypted key material is never seen.
     */
    public void addKeyBag(PKCS12KeyInfo keyInfo, Password password,
            SEQUENCE encSafeContents) throws Exception {
        logger.debug("Creating key bag for " + keyInfo.subjectDN);

        byte[] epkiBytes = keyInfo.getEncryptedPrivateKeyInfoBytes();
        if (epkiBytes == null) {
            PrivateKey k = keyInfo.getPrivateKey();
            if (k == null) {
                logger.debug("NO PRIVATE KEY for " + keyInfo.subjectDN);
                return;
            }
            logger.debug("Encrypting private key for " + keyInfo.subjectDN);

            epkiBytes = CryptoManager.getInstance()
                .getInternalKeyStorageToken()
                .getCryptoStore()
                .getEncryptedPrivateKeyInfo(
                    /* For compatibility with OpenSSL and NSS >= 3.31,
                     * do not BMPString-encode the passphrase when using
                     * non-PKCS #12 PBE scheme such as PKCS #5 PBES2.
                     *
                     * The resulting PKCS #12 is not compatible with
                     * NSS < 3.31.
                     */
                    null /* passConverter */,
                    password,
                    /* NSS has a bug that causes any AES CBC encryption
                     * to use AES-256, but AlgorithmID contains chosen
                     * alg.  To avoid mismatch, use AES_256_CBC. */
                    EncryptionAlgorithm.AES_256_CBC,
                    0 /* iterations (default) */,
                    k);
        }

        SET keyAttrs = createKeyBagAttrs(keyInfo);

        SafeBag safeBag = new SafeBag(
            SafeBag.PKCS8_SHROUDED_KEY_BAG, new ANY(epkiBytes), keyAttrs);
        encSafeContents.addElement(safeBag);
    }

    public void addCertBag(PKCS12CertInfo certInfo,
            SEQUENCE safeContents) throws Exception {

        logger.debug("Creating cert bag for " + certInfo.nickname);

        ASN1Value cert = new OCTET_STRING(certInfo.cert.getEncoded());
        CertBag certBag = new CertBag(CertBag.X509_CERT_TYPE, cert);

        SET certAttrs = createCertBagAttrs(certInfo);

        SafeBag safeBag = new SafeBag(SafeBag.CERT_BAG, certBag, certAttrs);
        safeContents.addElement(safeBag);
    }

    BigInteger createLocalID(X509Certificate cert) throws Exception {
        // SHA1 hash of the X509Cert DER encoding
        return createLocalID(cert.getEncoded());
    }

    BigInteger createLocalID(byte[] bytes) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(bytes);
        return new BigInteger(1, md.digest());
    }

    SET createKeyBagAttrs(PKCS12KeyInfo keyInfo) throws Exception {

        SET attrs = new SET();

        SEQUENCE subjectAttr = new SEQUENCE();
        subjectAttr.addElement(SafeBag.FRIENDLY_NAME);

        SET subjectSet = new SET();
        subjectSet.addElement(new BMPString(keyInfo.subjectDN));
        subjectAttr.addElement(subjectSet);

        attrs.addElement(subjectAttr);

        SEQUENCE localKeyAttr = new SEQUENCE();
        localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);

        SET localKeySet = new SET();
        localKeySet.addElement(new OCTET_STRING(keyInfo.id.toByteArray()));
        localKeyAttr.addElement(localKeySet);

        attrs.addElement(localKeyAttr);

        return attrs;
    }

    SET createCertBagAttrs(PKCS12CertInfo certInfo) throws Exception {

        SET attrs = new SET();

        SEQUENCE nicknameAttr = new SEQUENCE();
        nicknameAttr.addElement(SafeBag.FRIENDLY_NAME);

        SET nicknameSet = new SET();
        nicknameSet.addElement(new BMPString(certInfo.nickname));
        nicknameAttr.addElement(nicknameSet);

        attrs.addElement(nicknameAttr);

        if (certInfo.getID() != null) {
            SEQUENCE localKeyAttr = new SEQUENCE();
            localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);

            SET localKeySet = new SET();
            localKeySet.addElement(new OCTET_STRING(certInfo.id.toByteArray()));
            localKeyAttr.addElement(localKeySet);

            attrs.addElement(localKeyAttr);
        }

        if (certInfo.trustFlags != null && trustFlagsEnabled) {
            SEQUENCE trustFlagsAttr = new SEQUENCE();
            trustFlagsAttr.addElement(PKCS12.CERT_TRUST_FLAGS_OID);

            SET trustFlagsSet = new SET();
            trustFlagsSet.addElement(new BMPString(certInfo.trustFlags));
            trustFlagsAttr.addElement(trustFlagsSet);

            attrs.addElement(trustFlagsAttr);
        }

        return attrs;
    }

    public void loadFromNSS(PKCS12 pkcs12) throws Exception {
        loadFromNSS(pkcs12, true, true);
    }

    public void loadFromNSS(PKCS12 pkcs12, boolean includeKey, boolean includeChain) throws Exception {

        logger.info("Loading all certificate and keys from NSS database");

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        for (X509Certificate cert : store.getCertificates()) {
            loadCertFromNSS(pkcs12, cert, includeKey, includeChain);
        }
    }

    public void loadCertFromNSS(PKCS12 pkcs12, String nickname, boolean includeKey, boolean includeChain) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        X509Certificate[] certs = cm.findCertsByNickname(nickname);
        for (X509Certificate cert : certs) {
            loadCertFromNSS(pkcs12, cert, includeKey, includeChain);
        }
    }

    public void loadCertFromNSS(PKCS12 pkcs12, X509Certificate cert, boolean includeKey, boolean includeChain) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        BigInteger id = createLocalID(cert);

        // load cert info
        loadCertInfoFromNSS(pkcs12, cert, id, true);

        if (includeKey) {
            // load key info if exists
            loadKeyInfoFromNSS(pkcs12, cert, id);
        }

        if (includeChain) {
            // load cert chain
            X509Certificate[] certChain = cm.buildCertificateChain(cert);
            for (int i = 1; i < certChain.length; i++) {
                X509Certificate c = certChain[i];
                BigInteger cid = createLocalID(c);
                loadCertInfoFromNSS(pkcs12, c, cid, false);
            }
        }
    }

    public void loadCertInfoFromNSS(PKCS12 pkcs12, X509Certificate cert, BigInteger id, boolean replace) throws Exception {

        String nickname = cert.getNickname();
        logger.info("Loading certificate \"" + nickname + "\" from NSS database");

        PKCS12CertInfo certInfo = new PKCS12CertInfo();
        certInfo.id = id;
        certInfo.nickname = nickname;
        certInfo.cert = new X509CertImpl(cert.getEncoded());
        certInfo.trustFlags = getTrustFlags(cert);

        pkcs12.addCertInfo(certInfo, replace);
    }

    public void loadKeyInfoFromNSS(PKCS12 pkcs12, X509Certificate cert, BigInteger id) throws Exception {

        String nickname = cert.getNickname();
        logger.info("Loading private key for certificate \"" + nickname + "\" from NSS database");

        CryptoManager cm = CryptoManager.getInstance();

        try {
            PrivateKey privateKey = cm.findPrivKeyByCert(cert);
            logger.debug("Certificate \"" + nickname + "\" has private key");

            PKCS12KeyInfo keyInfo = new PKCS12KeyInfo(privateKey);
            keyInfo.id = id;
            keyInfo.subjectDN = cert.getSubjectDN().toString();

            pkcs12.addKeyInfo(keyInfo);

        } catch (ObjectNotFoundException e) {
            logger.debug("Certificate \"" + nickname + "\" has no private key");
        }
    }

    public PFX generatePFX(PKCS12 pkcs12, Password password) throws Exception {

        logger.info("Generating PKCS #12 data");

        SEQUENCE safeContents = new SEQUENCE();

        for (PKCS12CertInfo certInfo : pkcs12.getCertInfos()) {
            addCertBag(certInfo, safeContents);
        }

        SEQUENCE encSafeContents = new SEQUENCE();

        for (PKCS12KeyInfo keyInfo : pkcs12.getKeyInfos()) {
            addKeyBag(keyInfo, password, encSafeContents);
        }

        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(safeContents);
        authSafes.addSafeContents(encSafeContents);

        PFX pfx = new PFX(authSafes);
        pfx.computeMacData(password, null, 5);

        return pfx;
    }

    public void storeIntoFile(PKCS12 pkcs12, String filename, Password password) throws Exception {

        PFX pfx = generatePFX(pkcs12, password);

        logger.info("Storing data into PKCS #12 file");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        pfx.encode(bos);
        byte[] data = bos.toByteArray();

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }

    /**
     * Loads key bags (for IMPORT and other operations on existing
     * PKCS #12 files).  Does not decrypt EncryptedPrivateKeyInfo
     * values, but stores them in PKCS12KeyInfo objects for possible
     * later use.
     */
    public PKCS12KeyInfo getKeyInfo(SafeBag bag, Password password) throws Exception {

        PKCS12KeyInfo keyInfo = new PKCS12KeyInfo(bag.getBagContent().getEncoded());

        // get key attributes
        SET bagAttrs = bag.getBagAttributes();

        for (int i = 0; bagAttrs != null && i < bagAttrs.size(); i++) {

            Attribute attr = (Attribute) bagAttrs.elementAt(i);
            OBJECT_IDENTIFIER oid = attr.getType();

            if (oid.equals(SafeBag.FRIENDLY_NAME)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                BMPString subjectDN = (BMPString) new BMPString.Template().decode(bis);

                keyInfo.subjectDN = subjectDN.toString();
                logger.debug("   Subject DN: " + keyInfo.subjectDN);

            } else if (oid.equals(SafeBag.LOCAL_KEY_ID)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                OCTET_STRING keyID = (OCTET_STRING) new OCTET_STRING.Template().decode(bis);

                keyInfo.id = new BigInteger(1, keyID.toByteArray());
                logger.debug("   ID: " + keyInfo.id.toString(16));
            }
        }

        return keyInfo;
    }

    public PKCS12CertInfo getCertInfo(SafeBag bag) throws Exception {

        PKCS12CertInfo certInfo = new PKCS12CertInfo();

        CertBag certBag = (CertBag) bag.getInterpretedBagContent();

        OCTET_STRING certStr = (OCTET_STRING) certBag.getInterpretedCert();
        byte[] x509cert = certStr.toByteArray();

        certInfo.cert = new X509CertImpl(x509cert);
        Principal subjectDN = certInfo.cert.getSubjectDN();
        logger.debug("   Subject DN: " + subjectDN);

        SET bagAttrs = bag.getBagAttributes();

        for (int i = 0; bagAttrs != null && i < bagAttrs.size(); i++) {

            Attribute attr = (Attribute) bagAttrs.elementAt(i);
            OBJECT_IDENTIFIER oid = attr.getType();

            if (oid.equals(SafeBag.FRIENDLY_NAME)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                BMPString nickname = (BMPString) (new BMPString.Template()).decode(bis);

                certInfo.nickname = nickname.toString();
                logger.debug("   Nickname: " + certInfo.nickname);


            } else if (oid.equals(SafeBag.LOCAL_KEY_ID)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                OCTET_STRING keyID = (OCTET_STRING) new OCTET_STRING.Template().decode(bis);

                certInfo.id = new BigInteger(1, keyID.toByteArray());
                logger.debug("   ID: " + certInfo.id.toString(16));

            } else if (oid.equals(PKCS12.CERT_TRUST_FLAGS_OID) && trustFlagsEnabled) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream is = new ByteArrayInputStream(value.getEncoded());
                BMPString trustFlags = (BMPString) (new BMPString.Template()).decode(is);

                certInfo.trustFlags = trustFlags.toString();
                logger.debug("   Trust flags: " + certInfo.trustFlags);
            }
        }

        if (certInfo.id == null) {
            logger.debug("   ID not specified, generating new ID");
            certInfo.id = createLocalID(x509cert);
            logger.debug("   ID: " + certInfo.id.toString(16));
        }

        if (certInfo.nickname == null) {
            logger.debug("   Nickname not specified, generating new nickname");
            DN dn = new DN(subjectDN.getName());
            String[] values = dn.explodeDN(true);
            certInfo.nickname = StringUtils.join(values, " - ");
            logger.debug("   Nickname: " + certInfo.nickname);
        }

        return certInfo;
    }

    public void getKeyInfos(PKCS12 pkcs12, PFX pfx, Password password) throws Exception {

        logger.debug("Load encrypted private keys:");

        AuthenticatedSafes safes = pfx.getAuthSafes();

        for (int i = 0; i < safes.getSize(); i++) {

            SEQUENCE contents = safes.getSafeContentsAt(password, i);

            for (int j = 0; j < contents.size(); j++) {

                SafeBag bag = (SafeBag) contents.elementAt(j);
                OBJECT_IDENTIFIER oid = bag.getBagType();

                if (!oid.equals(SafeBag.PKCS8_SHROUDED_KEY_BAG)) continue;

                logger.debug(" - Private key:");
                PKCS12KeyInfo keyInfo = getKeyInfo(bag, password);
                pkcs12.addKeyInfo(keyInfo);
            }
        }
    }

    public void getCertInfos(PKCS12 pkcs12, PFX pfx, Password password) throws Exception {

        logger.debug("Loading certificates:");

        AuthenticatedSafes safes = pfx.getAuthSafes();

        for (int i = 0; i < safes.getSize(); i++) {

            SEQUENCE contents = safes.getSafeContentsAt(password, i);

            for (int j = 0; j < contents.size(); j++) {

                SafeBag bag = (SafeBag) contents.elementAt(j);
                OBJECT_IDENTIFIER oid = bag.getBagType();

                if (!oid.equals(SafeBag.CERT_BAG)) continue;

                logger.debug(" - Certificate:");
                PKCS12CertInfo certInfo = getCertInfo(bag);
                pkcs12.addCertInfo(certInfo, true);
            }
        }
    }

    public PKCS12 loadFromFile(String filename, Password password) throws Exception {

        logger.info("Loading PKCS #12 file");

        Path path = Paths.get(filename);
        byte[] b = Files.readAllBytes(path);
        return loadFromByteArray(b, password);
    }

    public PKCS12 loadFromByteArray(byte[] b, Password password) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(b);

        PFX pfx = (PFX) (new PFX.Template()).decode(bis);

        PKCS12 pkcs12 = new PKCS12();

        StringBuffer reason = new StringBuffer();
        boolean valid = pfx.verifyAuthSafes(password, reason);

        if (!valid) {
            throw new Exception("Unable to validate PKCS #12 file: " + reason);
        }

        getKeyInfos(pkcs12, pfx, password);
        getCertInfos(pkcs12, pfx, password);

        return pkcs12;
    }

    public PKCS12 loadFromFile(String filename) throws Exception {
        return loadFromFile(filename, null);
    }

    public PrivateKey.Type getPrivateKeyType(PublicKey publicKey) {
        if (publicKey.getAlgorithm().equals("EC")) {
            return PrivateKey.Type.EC;
        }
        return PrivateKey.Type.RSA;
    }

    public PKCS12CertInfo getCertBySubjectDN(PKCS12 pkcs12, String subjectDN)
            throws CertificateException {

        for (PKCS12CertInfo certInfo : pkcs12.getCertInfos()) {
            Principal certSubjectDN = certInfo.cert.getSubjectDN();
            if (LDAPDN.equals(certSubjectDN.toString(), subjectDN)) return certInfo;
        }

        return null;
    }

    public void importKey(
            PKCS12 pkcs12,
            Password password,
            String nickname,
            PKCS12KeyInfo keyInfo) throws Exception {

        logger.debug("Importing private key " + keyInfo.subjectDN);

        PKCS12CertInfo certInfo = pkcs12.getCertInfoByID(keyInfo.getID());
        if (certInfo == null) {
            logger.debug("Private key has no certificate, ignore");
            return;
        }

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        X509Certificate cert = cm.importCACertPackage(certInfo.cert.getEncoded());

        // get public key
        PublicKey publicKey = cert.getPublicKey();

        byte[] epkiBytes = keyInfo.getEncryptedPrivateKeyInfoBytes();
        if (epkiBytes == null) {
            logger.debug(
                "No EncryptedPrivateKeyInfo for key '"
                + keyInfo.subjectDN + "'; skipping key");
        }
        try {
            // first true without BMPString-encoding the passphrase.
            store.importEncryptedPrivateKeyInfo(
                null, password, nickname, publicKey, epkiBytes);
        } catch (Exception e) {
            // if that failed, try again with BMPString-encoded
            // passphrase.  This is required for PKCS #12 PBE
            // schemes and for PKCS #12 files using PBES2 generated
            // by NSS < 3.31
            store.importEncryptedPrivateKeyInfo(
                new PasswordConverter(), password, nickname, publicKey, epkiBytes);
        }

        // delete the cert again (it will be imported again later
        // with the correct nickname)
        try {
            store.deleteCert(cert);
        } catch (NoSuchItemOnTokenException e) {
            // this is OK
        }
    }

    /**
     * Store a certificate (and key, if present) in NSSDB.
     */
    public void storeCertIntoNSS(
            PKCS12 pkcs12, Password password,
            PKCS12CertInfo certInfo, boolean overwrite)
        throws Exception
    {
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken ct = cm.getInternalKeyStorageToken();
        CryptoStore store = ct.getCryptoStore();

        BigInteger id = certInfo.getID();
        PKCS12KeyInfo keyInfo = pkcs12.getKeyInfoByID(id);

        for (X509Certificate cert : cm.findCertsByNickname(certInfo.nickname)) {
            if (!overwrite) {
                return;
            }
            store.deleteCert(cert);
        }

        X509Certificate cert;
        if (keyInfo != null) { // cert has key
            logger.debug("Importing user key for " + certInfo.nickname);
            importKey(pkcs12, password, certInfo.nickname, keyInfo);

            logger.debug("Importing user certificate " + certInfo.nickname);
            cert = cm.importUserCACertPackage(certInfo.cert.getEncoded(), certInfo.nickname);

        } else { // cert has no key
            logger.debug("Importing CA certificate " + certInfo.nickname);
            // Note: JSS does not preserve CA certificate nickname
            cert = cm.importCACertPackage(certInfo.cert.getEncoded());
        }

        if (certInfo.trustFlags != null && trustFlagsEnabled)
            setTrustFlags(cert, certInfo.trustFlags);
    }

    public void storeCertIntoNSS(PKCS12 pkcs12, Password password, String nickname, boolean overwrite) throws Exception {
        Collection<PKCS12CertInfo> certInfos = pkcs12.getCertInfosByNickname(nickname);
        for (PKCS12CertInfo certInfo : certInfos) {
            storeCertIntoNSS(pkcs12, password, certInfo, overwrite);
        }
    }

    public void storeIntoNSS(
            PKCS12 pkcs12, Password password, boolean overwrite)
        throws Exception
    {
        logger.info("Storing data into NSS database");

        for (PKCS12CertInfo certInfo : pkcs12.getCertInfos()) {
            storeCertIntoNSS(pkcs12, password, certInfo, overwrite);
        }
    }
}
