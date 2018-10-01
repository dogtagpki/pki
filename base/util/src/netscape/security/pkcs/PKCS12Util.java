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
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
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
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Store;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import netscape.ldap.LDAPDN;
import netscape.ldap.util.DN;
import netscape.security.x509.X509CertImpl;

public class PKCS12Util {

    private static Logger logger = LoggerFactory.getLogger(PKCS12Util.class);

    public final static String NO_ENCRYPTION = "none";

    public final static List<PBEAlgorithm> SUPPORTED_CERT_ENCRYPTIONS = Arrays.asList(new PBEAlgorithm[] {
            null, // none
            PBEAlgorithm.PBE_SHA1_RC2_40_CBC
    });

    public final static List<PBEAlgorithm> SUPPORTED_KEY_ENCRYPTIONS = Arrays.asList(new PBEAlgorithm[] {
            PBEAlgorithm.PBE_PKCS5_PBES2,
            PBEAlgorithm.PBE_SHA1_DES3_CBC
    });

    public final static PBEAlgorithm DEFAULT_CERT_ENCRYPTION = SUPPORTED_CERT_ENCRYPTIONS.get(0);
    public final static String DEFAULT_CERT_ENCRYPTION_NAME = NO_ENCRYPTION;

    public final static PBEAlgorithm DEFAULT_KEY_ENCRYPTION = SUPPORTED_KEY_ENCRYPTIONS.get(0);
    public final static String DEFAULT_KEY_ENCRYPTION_NAME = DEFAULT_KEY_ENCRYPTION.toString();

    SecureRandom random;
    PBEAlgorithm certEncryption = DEFAULT_CERT_ENCRYPTION;
    PBEAlgorithm keyEncryption = DEFAULT_KEY_ENCRYPTION;
    boolean trustFlagsEnabled = true;

    public PKCS12Util() throws Exception {
        random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
    }

    public void setCertEncryption(String name) throws Exception {

        for (PBEAlgorithm algorithm : SUPPORTED_CERT_ENCRYPTIONS) {

            if (algorithm == null) {
                if (NO_ENCRYPTION.equals(name)) {
                    this.certEncryption = null;
                    return;
                }

            } else if (algorithm.toString().equals(name)) {
                this.certEncryption = algorithm;
                return;
            }
        }

        throw new Exception("Unsupported certificate encryption: " + name);
    }

    public void setCertEncryption(PBEAlgorithm algorithm) throws Exception {
        this.certEncryption = algorithm;
    }

    public PBEAlgorithm getCertEncryption() {
        return certEncryption;
    }

    public void setKeyEncryption(String name) throws Exception {

        for (PBEAlgorithm algorithm : SUPPORTED_KEY_ENCRYPTIONS) {

            if (algorithm == null) {
                if (NO_ENCRYPTION.equals(name)) {
                    this.keyEncryption = null;
                    return;
                }

            } else if (algorithm.toString().equals(name)) {
                this.keyEncryption = algorithm;
                return;
            }
        }

        throw new Exception("Unsupported key encryption: " + name);
    }

    public void setKeyEncryption(PBEAlgorithm algorithm) throws Exception {
        this.keyEncryption = algorithm;
    }

    public PBEAlgorithm getKeyEncryption() {
        return keyEncryption;
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

        String[] flags = trustFlags.split(",", -1); // don't remove empty string
        if (flags.length < 3) throw new Exception("Invalid trust flags: " + trustFlags);

        icert.setSSLTrust(PKCS12.decodeFlags(flags[0]));
        icert.setEmailTrust(PKCS12.decodeFlags(flags[1]));
        icert.setObjectSigningTrust(PKCS12.decodeFlags(flags[2]));
    }

    /**
     * Add a private key to the PKCS #12 object.
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

        byte[] keyID = keyInfo.getID();
        logger.debug(" - Key ID: " + Hex.encodeHexString(keyID));

        ASN1Value content;

        byte[] epkiBytes = keyInfo.getEncryptedPrivateKeyInfoBytes();

        if (epkiBytes != null) {
            // private key already encrypted
            content = new ANY(epkiBytes);

        } else {
            PrivateKey privateKey = keyInfo.getPrivateKey();
            if (privateKey == null) {
                throw new Exception("Missing private key for " + keyInfo.getFriendlyName());
            }

            CryptoToken token = CryptoManager.getInstance().getInternalKeyStorageToken();

            if (keyEncryption == PBEAlgorithm.PBE_SHA1_DES3_CBC) {
                content = create_EPKI_with_PBE_SHA1_DES3_CBC(token, privateKey, password);

            } else if (keyEncryption == PBEAlgorithm.PBE_PKCS5_PBES2) {
                content = create_EPKI_with_PBE_PKCS5_PBES2(token, privateKey, password);

            } else {
                throw new Exception("Unsupported key encryption: " + keyEncryption);
            }
        }

        SET keyAttrs = createKeyBagAttrs(keyInfo);

        SafeBag safeBag = new SafeBag(SafeBag.PKCS8_SHROUDED_KEY_BAG, content, keyAttrs);
        encSafeContents.addElement(safeBag);
    }

    public ASN1Value create_EPKI_with_PBE_SHA1_DES3_CBC(CryptoToken token, PrivateKey privateKey, Password password)
            throws Exception {

        // Use the same salt size and number of iterations as in pk12util.

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        return EncryptedPrivateKeyInfo.createPBE(
                PBEAlgorithm.PBE_SHA1_DES3_CBC,
                password,
                salt,
                100000, // iterations
                new PasswordConverter(),
                privateKey,
                token);
    }

    public ASN1Value create_EPKI_with_PBE_PKCS5_PBES2(CryptoToken token, PrivateKey privateKey, Password password)
            throws Exception {

        CryptoStore store = token.getCryptoStore();

        byte[] bytes = store.getEncryptedPrivateKeyInfo(
                // For compatibility with OpenSSL and NSS >= 3.31,
                // do not BMPString-encode the passphrase when using
                // non-PKCS #12 PBE scheme such as PKCS #5 PBES2.
                //
                // The resulting PKCS #12 is not compatible with
                // NSS < 3.31.
                null, // password converter
                password,
                // NSS has a bug that causes any AES CBC encryption
                // to use AES-256, but AlgorithmID contains chosen
                // alg.  To avoid mismatch, use AES_256_CBC.
                EncryptionAlgorithm.AES_256_CBC,
                0, // iterations (default)
                privateKey);

        return new ANY(bytes);
    }

    public void addCertBag(PKCS12CertInfo certInfo,
            SEQUENCE safeContents) throws Exception {

        byte[] id = certInfo.getID();
        logger.debug(" - Certificate ID: " + Hex.encodeHexString(id));

        X509CertImpl cert = certInfo.getCert();
        ASN1Value certAsn1 = new OCTET_STRING(cert.getEncoded());
        CertBag certBag = new CertBag(CertBag.X509_CERT_TYPE, certAsn1);

        SET certAttrs = createCertBagAttrs(certInfo);

        SafeBag safeBag = new SafeBag(SafeBag.CERT_BAG, certBag, certAttrs);
        safeContents.addElement(safeBag);
    }

    SET createKeyBagAttrs(PKCS12KeyInfo keyInfo) throws Exception {

        SET attrs = new SET();

        String friendlyName = keyInfo.getFriendlyName();
        logger.debug("   Friendly name: " + friendlyName);

        SEQUENCE subjectAttr = new SEQUENCE();
        subjectAttr.addElement(SafeBag.FRIENDLY_NAME);

        SET subjectSet = new SET();
        subjectSet.addElement(new BMPString(friendlyName));
        subjectAttr.addElement(subjectSet);

        attrs.addElement(subjectAttr);

        byte[] keyID = keyInfo.getID();

        SEQUENCE localKeyAttr = new SEQUENCE();
        localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);

        SET localKeySet = new SET();
        localKeySet.addElement(new OCTET_STRING(keyID));
        localKeyAttr.addElement(localKeySet);

        attrs.addElement(localKeyAttr);

        return attrs;
    }

    SET createCertBagAttrs(PKCS12CertInfo certInfo) throws Exception {

        SET attrs = new SET();

        String friendlyName = certInfo.getFriendlyName();
        logger.debug("   Friendly name: " + friendlyName);

        SEQUENCE nicknameAttr = new SEQUENCE();
        nicknameAttr.addElement(SafeBag.FRIENDLY_NAME);

        SET nicknameSet = new SET();
        nicknameSet.addElement(new BMPString(friendlyName));
        nicknameAttr.addElement(nicknameSet);

        attrs.addElement(nicknameAttr);

        String trustFlags = certInfo.getTrustFlags();
        if (trustFlags != null && trustFlagsEnabled) {
            logger.debug("   Trust flags: " + trustFlags);

            SEQUENCE trustFlagsAttr = new SEQUENCE();
            trustFlagsAttr.addElement(PKCS12.CERT_TRUST_FLAGS_OID);

            SET trustFlagsSet = new SET();
            trustFlagsSet.addElement(new BMPString(trustFlags));
            trustFlagsAttr.addElement(trustFlagsSet);

            attrs.addElement(trustFlagsAttr);
        }

        byte[] keyID = certInfo.getID();
        if (keyID != null) {
            logger.debug("   Key ID: " + Hex.encodeHexString(keyID));

            SEQUENCE localKeyAttr = new SEQUENCE();
            localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);

            SET localKeySet = new SET();
            localKeySet.addElement(new OCTET_STRING(keyID));
            localKeyAttr.addElement(localKeySet);

            attrs.addElement(localKeyAttr);
        }

        return attrs;
    }

    public void loadFromNSS(PKCS12 pkcs12) throws Exception {
        loadFromNSS(pkcs12, true, true);
    }

    public void loadFromNSS(PKCS12 pkcs12, boolean includeKey, boolean includeChain) throws Exception {

        logger.info("Loading certificates and keys from NSS database");

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        for (X509Certificate cert : store.getCertificates()) {
            loadCertFromNSS(pkcs12, cert, includeKey, includeChain);
        }
    }

    public void loadCertFromNSS(
            PKCS12 pkcs12,
            String nickname,
            boolean includeKey,
            boolean includeChain) throws Exception {

        loadCertFromNSS(pkcs12, nickname, includeKey, includeChain, null);
    }

    public void loadCertFromNSS(
            PKCS12 pkcs12,
            String nickname,
            boolean includeKey,
            boolean includeChain,
            String friendlyName) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        X509Certificate[] certs = cm.findCertsByNickname(nickname);

        if (certs == null || certs.length == 0) {
            throw new Exception("Certificate not found: " + nickname);
        }

        for (X509Certificate cert : certs) {
            loadCertFromNSS(pkcs12, cert, includeKey, includeChain, friendlyName);
        }
    }

    public void loadCertFromNSS(
            PKCS12 pkcs12,
            X509Certificate cert,
            boolean includeKey,
            boolean includeChain) throws Exception {

        loadCertFromNSS(pkcs12, cert, includeKey, includeChain, null);
    }

    public void loadCertFromNSS(
            PKCS12 pkcs12,
            X509Certificate cert,
            boolean includeKey,
            boolean includeChain,
            String friendlyName) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();

        PKCS12CertInfo certInfo = createCertInfoFromNSS(cert, friendlyName);
        pkcs12.addCertInfo(certInfo, true);

        byte[] id = certInfo.getID();
        logger.debug(" - Certificate ID: " + Hex.encodeHexString(id));
        logger.debug("   Friendly name: " + certInfo.getFriendlyName());
        logger.debug("   Trust flags: " + certInfo.getTrustFlags());

        if (includeKey) {
            // load key info if exists

            try {
                PrivateKey privateKey = cm.findPrivKeyByCert(cert);

                PKCS12KeyInfo keyInfo = createKeyInfoFromNSS(cert, privateKey, id, friendlyName);
                pkcs12.addKeyInfo(keyInfo);

                byte[] keyID = keyInfo.getID();
                logger.debug("   Key ID: " + Hex.encodeHexString(keyID));

            } catch (ObjectNotFoundException e) {
                logger.debug("Certificate has no private key");
            }
        }

        if (includeChain) {
            // load cert chain
            X509Certificate[] certChain = cm.buildCertificateChain(cert);
            if (certChain.length > 1) {
                logger.debug("   Certificate Chain:");
            }
            for (int i = 1; i < certChain.length; i++) {
                X509Certificate caCert = certChain[i];

                PKCS12CertInfo caCertInfo = createCertInfoFromNSS(caCert);
                pkcs12.addCertInfo(caCertInfo, false);

                byte[] caCertID = caCertInfo.getID();
                logger.debug("   - Certificate ID: " + Hex.encodeHexString(caCertID));
                logger.debug("     Friendly name: " + caCertInfo.getFriendlyName());
                logger.debug("     Trust flags: " + caCertInfo.getTrustFlags());
            }
        }
    }

    public PKCS12CertInfo createCertInfoFromNSS(
            X509Certificate cert) throws Exception {

        return createCertInfoFromNSS(cert, null);
    }

    public PKCS12CertInfo createCertInfoFromNSS(
            X509Certificate cert,
            String friendlyName) throws Exception {

        // generate cert ID from SHA-1 hash of cert data
        byte[] id = SafeBag.getLocalKeyIDFromCert(cert.getEncoded());

        if (friendlyName == null) {
            friendlyName = cert.getNickname();
        }

        X509CertImpl certImpl = new X509CertImpl(cert.getEncoded());
        String trustFlags = getTrustFlags(cert);

        PKCS12CertInfo certInfo = new PKCS12CertInfo();
        certInfo.setID(id);
        certInfo.setFriendlyName(friendlyName);
        certInfo.setCert(certImpl);
        certInfo.setTrustFlags(trustFlags);

        return certInfo;
    }

    public PKCS12KeyInfo createKeyInfoFromNSS(
            X509Certificate cert,
            PrivateKey privateKey,
            byte[] id) throws Exception {

        return createKeyInfoFromNSS(cert, privateKey, id, null);
    }

    public PKCS12KeyInfo createKeyInfoFromNSS(
            X509Certificate cert,
            PrivateKey privateKey,
            byte[] id,
            String friendlyName) throws Exception {

        if (friendlyName == null) {
            friendlyName = cert.getNickname();
        }

        PKCS12KeyInfo keyInfo = new PKCS12KeyInfo(privateKey);
        keyInfo.setID(id);
        keyInfo.setFriendlyName(friendlyName);

        return keyInfo;
    }

    public PFX generatePFX(PKCS12 pkcs12, Password password) throws Exception {

        logger.info("Generating PKCS #12 data");

        AuthenticatedSafes authSafes = new AuthenticatedSafes();

        Collection<PKCS12KeyInfo> keyInfos = pkcs12.getKeyInfos();
        Collection<PKCS12CertInfo> certInfos = pkcs12.getCertInfos();

        if (!keyInfos.isEmpty()) {
            SEQUENCE keySafeContents = new SEQUENCE();

            for (PKCS12KeyInfo keyInfo : keyInfos) {
                addKeyBag(keyInfo, password, keySafeContents);
            }

            authSafes.addSafeContents(keySafeContents);
        }

        if (!certInfos.isEmpty()) {
            SEQUENCE certSafeContents = new SEQUENCE();

            for (PKCS12CertInfo certInfo : certInfos) {
                addCertBag(certInfo, certSafeContents);
            }

            if (certEncryption == null) {
                authSafes.addSafeContents(certSafeContents);

            } else if (certEncryption == PBEAlgorithm.PBE_SHA1_RC2_40_CBC) {

                byte[] salt = new byte[16];
                random.nextBytes(salt);

                authSafes.addEncryptedSafeContents(
                        certEncryption,
                        password,
                        salt,
                        100000, // iterations
                        certSafeContents);

            } else {
                throw new Exception("Unsupported certificate encryption: " + certEncryption);
            }
        }

        PFX pfx = new PFX(authSafes);

        // Use the same salt size and number of iterations as in pk12util.

        byte[] salt = new byte[16];
        random.nextBytes(salt);
        pfx.computeMacData(password, salt, 100000);

        return pfx;
    }

    public void storeIntoFile(PKCS12 pkcs12, String filename, Password password) throws Exception {

        PFX pfx = generatePFX(pkcs12, password);

        logger.info("Storing PKCS #12 data into " + filename);
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
                BMPString friendlyName = (BMPString) new BMPString.Template().decode(bis);

                keyInfo.setFriendlyName(friendlyName.toString());
                logger.debug("   Friendly name: " + keyInfo.getFriendlyName());

            } else if (oid.equals(SafeBag.LOCAL_KEY_ID)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                OCTET_STRING keyIdAsn1 = (OCTET_STRING) new OCTET_STRING.Template().decode(bis);

                byte[] keyID = keyIdAsn1.toByteArray();
                keyInfo.setID(keyID);

            } else {
                logger.warn("   " + oid + ": " + attr.getValues());
            }
        }

        return keyInfo;
    }

    public PKCS12CertInfo getCertInfo(SafeBag bag) throws Exception {

        PKCS12CertInfo certInfo = new PKCS12CertInfo();

        CertBag certBag = (CertBag) bag.getInterpretedBagContent();

        OCTET_STRING certStr = (OCTET_STRING) certBag.getInterpretedCert();
        byte[] x509cert = certStr.toByteArray();

        X509CertImpl cert = new X509CertImpl(x509cert);
        certInfo.setCert(cert);

        Principal subjectDN = cert.getSubjectDN();
        logger.debug("   Subject DN: " + subjectDN);

        SET bagAttrs = bag.getBagAttributes();

        for (int i = 0; bagAttrs != null && i < bagAttrs.size(); i++) {

            Attribute attr = (Attribute) bagAttrs.elementAt(i);
            OBJECT_IDENTIFIER oid = attr.getType();

            if (oid.equals(SafeBag.FRIENDLY_NAME)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                BMPString friendlyName = (BMPString) (new BMPString.Template()).decode(bis);

                certInfo.setFriendlyName(friendlyName.toString());
                logger.debug("   Friendly name: " + certInfo.getFriendlyName());

            } else if (oid.equals(SafeBag.LOCAL_KEY_ID)) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream bis = new ByteArrayInputStream(value.getEncoded());
                OCTET_STRING keyIdAsn1 = (OCTET_STRING) new OCTET_STRING.Template().decode(bis);

                byte[] keyID = keyIdAsn1.toByteArray();
                certInfo.setID(keyID);
                logger.debug("   Key ID: " + Hex.encodeHexString(keyID));

            } else if (oid.equals(PKCS12.CERT_TRUST_FLAGS_OID) && trustFlagsEnabled) {

                SET values = attr.getValues();
                ANY value = (ANY) values.elementAt(0);

                ByteArrayInputStream is = new ByteArrayInputStream(value.getEncoded());
                BMPString trustFlagsAsn1 = (BMPString) (new BMPString.Template()).decode(is);

                String trustFlags = trustFlagsAsn1.toString();
                certInfo.setTrustFlags(trustFlags);
                logger.debug("   Trust flags: " + trustFlags);
            }
        }

        byte[] id = certInfo.getID();
        if (id == null) {
            logger.debug("   ID not specified, generating new ID");
            // generate cert ID from SHA-1 hash of cert data
            id = SafeBag.getLocalKeyIDFromCert(x509cert);
            certInfo.setID(id);
            logger.debug("   ID: " + Hex.encodeHexString(id));
        }

        if (certInfo.getFriendlyName() == null) {
            logger.debug("   Generating new friendly name");
            DN dn = new DN(subjectDN.getName());
            String[] values = dn.explodeDN(true);
            String friendlyName = StringUtils.join(values, " - ");
            certInfo.setFriendlyName(friendlyName);
            logger.debug("   Friendly name: " + friendlyName);
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
            X509CertImpl cert = certInfo.getCert();
            Principal certSubjectDN = cert.getSubjectDN();
            if (LDAPDN.equals(certSubjectDN.toString(), subjectDN)) return certInfo;
        }

        return null;
    }

    public void importKey(
            PKCS12 pkcs12,
            Password password,
            String nickname,
            PKCS12KeyInfo keyInfo) throws Exception {

        PKCS12CertInfo certInfo = pkcs12.getCertInfoByID(keyInfo.getID());
        if (certInfo == null) {
            logger.debug("Private key has no certificate, ignore");
            return;
        }

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        PK11Store store = (PK11Store)token.getCryptoStore();

        X509CertImpl certImpl = certInfo.getCert();
        X509Certificate cert = cm.importCACertPackage(certImpl.getEncoded());

        // get public key
        PublicKey publicKey = cert.getPublicKey();

        byte[] epkiBytes = keyInfo.getEncryptedPrivateKeyInfoBytes();
        if (epkiBytes == null) {
            logger.debug(
                "No EncryptedPrivateKeyInfo for key '"
                + keyInfo.getFriendlyName() + "'; skipping key");
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
            store.deleteCertOnly(cert);
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

        byte[] id = certInfo.getID();
        PKCS12KeyInfo keyInfo = pkcs12.getKeyInfoByID(id);

        String nickname = certInfo.getFriendlyName();
        for (X509Certificate cert : cm.findCertsByNickname(nickname)) {
            if (!overwrite) {
                return;
            }
            store.deleteCert(cert);
        }

        X509CertImpl certImpl = certInfo.getCert();
        X509Certificate cert;
        if (keyInfo != null) { // cert has key
            logger.debug("Importing private key for " + certInfo.getFriendlyName());
            importKey(pkcs12, password, certInfo.getFriendlyName(), keyInfo);

            logger.debug("Importing user certificate " + certInfo.getFriendlyName());
            cert = cm.importUserCACertPackage(
                    certImpl.getEncoded(), certInfo.getFriendlyName());

        } else { // cert has no key
            logger.debug("Importing CA certificate " + certInfo.getFriendlyName());
            // Note: JSS does not preserve CA certificate nickname
            cert = cm.importCACertPackage(certImpl.getEncoded());
        }

        String trustFlags = certInfo.getTrustFlags();
        if (trustFlags != null && trustFlagsEnabled) {
            setTrustFlags(cert, trustFlags);
        }
    }

    public void storeCertIntoNSS(PKCS12 pkcs12, Password password, String nickname, boolean overwrite) throws Exception {
        Collection<PKCS12CertInfo> certInfos = pkcs12.getCertInfosByFriendlyName(nickname);
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
