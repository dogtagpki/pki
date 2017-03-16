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
package com.netscape.kra;

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Random;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.kra.EKRAException;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.security.Credential;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerValue;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

/**
 * A class represents recovery request processor. There
 * are 2 types of recovery modes: (1) administrator or
 * (2) end-entity.
 * <P>
 * Administrator recovery will create a PKCS12 file where stores the certificate and the recovered key.
 * <P>
 * End Entity recovery will send RA or CA a response where stores the recovered key.
 *
 * @author thomask (original)
 * @author cfu (non-RSA keys; private keys secure handling);
 * @version $Revision$, $Date$
 */
public class RecoveryService implements IService {

    public static final String ATTR_NICKNAME = "nickname";
    public static final String ATTR_OWNER_NAME = "ownerName";
    public static final String ATTR_SERIALNO = "serialNumber";
    public static final String ATTR_PUBLIC_KEY_DATA = "publicKeyData";
    public static final String ATTR_PRIVATE_KEY_DATA = "privateKeyData";
    public static final String ATTR_TRANSPORT_CERT = "transportCert";
    public static final String ATTR_TRANSPORT_PWD = "transportPwd";
    public static final String ATTR_SIGNING_CERT = "signingCert";
    public static final String ATTR_PKCS12 = "pkcs12";
    public static final String ATTR_ENCRYPTION_CERTS =
            "encryptionCerts";
    public static final String ATTR_AGENT_CREDENTIALS =
            "agentCredentials";
    // same as encryption certs
    public static final String ATTR_USER_CERT = "cert";
    public static final String ATTR_DELIVERY = "delivery";

    private IKeyRecoveryAuthority mKRA = null;
    private IKeyRepository mStorage = null;
    private IStorageKeyUnit mStorageUnit = null;

    /**
     * Constructs request processor.
     */
    public RecoveryService(IKeyRecoveryAuthority kra) {
        mKRA = kra;
        mStorage = mKRA.getKeyRepository();
        mStorageUnit = mKRA.getStorageKeyUnit();
    }

    /**
     * Processes a recovery request. Based on the recovery mode
     * (either Administrator or End-Entity), the method reads
     * the key record from the database, and tried to recover the
     * key with the storage key unit.
     *
     * @param request recovery request
     * @return operation success or not
     * @exception EBaseException failed to serve
     */
    public boolean serviceRequest(IRequest request) throws EBaseException {

        CryptoManager cm = null;
        IConfigStore config = null;
        String tokName = "";
        CryptoToken ct = null;
        Boolean allowEncDecrypt_recovery = false;

        try {
            cm = CryptoManager.getInstance();
            config = CMS.getConfigStore();
            tokName = config.getString("kra.storageUnit.hardware", CryptoUtil.INTERNAL_TOKEN_NAME);
            CMS.debug("RecoveryService: serviceRequest: token: " + tokName);
            ct = CryptoUtil.getCryptoToken(tokName);

            allowEncDecrypt_recovery = config.getBoolean("kra.allowEncDecrypt.recovery", false);
        } catch (Exception e) {
            CMS.debug("RecoveryService exception: use internal token :"
                    + e.toString());
            ct = cm.getInternalCryptoToken();
        }
        if (ct == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR" + "cannot get crypto token"));
        }

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("recovery", true /* main action */);
        }

        if (Debug.ON)
            Debug.trace("KRA services recovery request");
        mKRA.log(ILogger.LL_INFO, "KRA services recovery request");

        // byte publicKey[] = (byte[])request.get(ATTR_PUBLIC_KEY_DATA);
        // X500Name owner = (X500Name)request.get(ATTR_OWNER_NAME);

        Hashtable<String, Object> params = mKRA.getVolatileRequest(
                request.getRequestId());

        if (params == null) {
            // possibly we are in recovery mode
            return true;
        }

        // retrieve based on serial no
        BigInteger serialno = request.getExtDataInBigInteger(ATTR_SERIALNO);

        mKRA.log(ILogger.LL_INFO, "KRA reading key record");
        if (statsSub != null) {
            statsSub.startTiming("get_key");
        }
        KeyRecord keyRecord = (KeyRecord) mStorage.readKeyRecord(serialno);
        if (statsSub != null) {
            statsSub.endTiming("get_key");
        }

        // see if the certificate matches the key
        byte pubData[] = keyRecord.getPublicKeyData();
        X509Certificate x509cert =
                request.getExtDataInCert(ATTR_USER_CERT);
        if (x509cert == null) {
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_INVALID_KEYRECORD"));
        }
        byte inputPubData[] = x509cert.getPublicKey().getEncoded();

        if (inputPubData.length != pubData.length) {
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PUBLIC_KEY_LEN"));
            throw new EKRAException(
                    CMS.getUserMessage("CMS_KRA_PUBLIC_KEY_NOT_MATCHED"));
        }
        for (int i = 0; i < pubData.length; i++) {
            if (pubData[i] != inputPubData[i]) {
                mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PUBLIC_KEY_LEN"));
                throw new EKRAException(
                        CMS.getUserMessage("CMS_KRA_PUBLIC_KEY_NOT_MATCHED"));
            }
        }

        boolean isRSA = true;
        String keyAlg = x509cert.getPublicKey().getAlgorithm();
        if (keyAlg != null) {
            CMS.debug("RecoveryService: publicKey alg =" + keyAlg);
            if (!keyAlg.equals("RSA"))
                isRSA = false;
        }

        // Unwrap the archived private key
        byte privateKeyData[] = null;
        X509Certificate transportCert =
                request.getExtDataInCert(ATTR_TRANSPORT_CERT);

        if (transportCert == null) {
            if (statsSub != null) {
                statsSub.startTiming("recover_key");
            }

            PrivateKey privKey = null;
            if (allowEncDecrypt_recovery == true) {
                privateKeyData = recoverKey(params, keyRecord);
            } else {
                privKey = recoverKey(params, keyRecord, isRSA);
            }
            if (statsSub != null) {
                statsSub.endTiming("recover_key");
            }

            if ((isRSA == true) && (allowEncDecrypt_recovery == true)) {
                if (statsSub != null) {
                    statsSub.startTiming("verify_key");
                }
                // verifyKeyPair() is RSA-centric
                if (verifyKeyPair(pubData, privateKeyData) == false) {
                    mKRA.log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSCORE_KRA_PUBLIC_NOT_FOUND"));
                    throw new EKRAException(
                            CMS.getUserMessage("CMS_KRA_INVALID_PUBLIC_KEY"));
                }
                if (statsSub != null) {
                    statsSub.endTiming("verify_key");
                }
            }

            if (statsSub != null) {
                statsSub.startTiming("create_p12");
            }
            if (allowEncDecrypt_recovery == true) {
                createPFX(request, params, privateKeyData);
            } else {
                createPFX(request, params, privKey, ct);
            }
            if (statsSub != null) {
                statsSub.endTiming("create_p12");
            }
        } else {

            if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
                Credential creds[] = (Credential[])
                        params.get(ATTR_AGENT_CREDENTIALS);
                mKRA.getStorageKeyUnit().login(creds);
            }
            if (statsSub != null) {
                statsSub.startTiming("unwrap_key");
            }

            try {
                mKRA.getStorageKeyUnit().unwrap(
                        keyRecord.getPrivateKeyData(),
                        null,
                        false,
                        keyRecord.getWrappingParams(mKRA.getStorageKeyUnit().getOldWrappingParams()));
            } catch (Exception e) {
                throw new EBaseException("Failed to unwrap private key", e);
            }

            if (statsSub != null) {
                statsSub.endTiming("unwrap_key");
            }

            if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
                mKRA.getStorageKeyUnit().logout();
            }
        }
        mKRA.log(ILogger.LL_INFO, "key " +
                serialno.toString() +
                " recovered");

        // for audit log
        String authMgr = AuditFormat.NOAUTH;
        String initiative = AuditFormat.FROMUSER;
        SessionContext sContext = SessionContext.getContext();

        if (sContext != null) {
            String agentId =
                    (String) sContext.get(SessionContext.USER_ID);

            initiative = AuditFormat.FROMAGENT + " agentID: " + agentId;
            AuthToken authToken = (AuthToken) sContext.get(SessionContext.AUTH_TOKEN);

            if (authToken != null) {
                authMgr =
                        authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
            }
        }
        CMS.getLogger().log(ILogger.EV_AUDIT,
                ILogger.S_KRA,
                AuditFormat.LEVEL,
                AuditFormat.FORMAT,
                new Object[] {
                        IRequest.KEYRECOVERY_REQUEST,
                        request.getRequestId(),
                        initiative,
                        authMgr,
                        "completed",
                        ((X509CertImpl) x509cert).getSubjectDN(),
                        "serial number: 0x" + serialno.toString(16) }
                );

        if (statsSub != null) {
            statsSub.endTiming("recovery");
        }

        return true;
    }

    /*
     * verifyKeyPair()- RSA-centric key verification
     */
    public boolean verifyKeyPair(byte publicKeyData[], byte privateKeyData[]) {
        try {
            DerValue publicKeyVal = new DerValue(publicKeyData);
            DerInputStream publicKeyIn = publicKeyVal.data;
            publicKeyIn.getSequence(0);
            DerValue publicKeyDer = new DerValue(publicKeyIn.getBitString());
            DerInputStream publicKeyDerIn = publicKeyDer.data;
            BigInt publicKeyModulus = publicKeyDerIn.getInteger();
            BigInt publicKeyExponent = publicKeyDerIn.getInteger();

            DerValue privateKeyVal = new DerValue(privateKeyData);
            if (privateKeyVal.tag != DerValue.tag_Sequence)
                return false;
            DerInputStream privateKeyIn = privateKeyVal.data;
            privateKeyIn.getInteger();
            privateKeyIn.getSequence(0);
            DerValue privateKeyDer = new DerValue(privateKeyIn.getOctetString());
            DerInputStream privateKeyDerIn = privateKeyDer.data;

            @SuppressWarnings("unused")
            BigInt privateKeyVersion = privateKeyDerIn.getInteger();
            BigInt privateKeyModulus = privateKeyDerIn.getInteger();
            BigInt privateKeyExponent = privateKeyDerIn.getInteger();

            if (!publicKeyModulus.equals(privateKeyModulus)) {
                CMS.debug("verifyKeyPair modulus mismatch publicKeyModulus="
                        + publicKeyModulus + " privateKeyModulus=" + privateKeyModulus);
                return false;
            }

            if (!publicKeyExponent.equals(privateKeyExponent)) {
                CMS.debug("verifyKeyPair exponent mismatch publicKeyExponent="
                        + publicKeyExponent + " privateKeyExponent=" + privateKeyExponent);
                return false;
            }

            return true;
        } catch (Exception e) {
            CMS.debug("verifyKeyPair error " + e);
            return false;
        }
    }

    /**
     * Recovers key. (using unwrapping/wrapping on token)
     * - used when allowEncDecrypt_recovery is false
     */
    public synchronized PrivateKey recoverKey(Hashtable<String, Object> request, KeyRecord keyRecord, boolean isRSA)
            throws EBaseException {

        CMS.debug("RecoverService: recoverKey: key to recover is RSA? "+
            isRSA);

        try {
            if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
                Credential creds[] = (Credential[])
                        request.get(ATTR_AGENT_CREDENTIALS);

                mStorageUnit.login(creds);
            }

            PublicKey pubkey = null;
            try {
                pubkey = X509Key.parsePublicKey(new DerValue(keyRecord.getPublicKeyData()));
            } catch (Exception e) {
                CMS.debug("RecoverService: after parsePublicKey:" + e.toString());
                throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1", "public key parsing failure"));
            }

            PrivateKey privKey = null;
            try {
                privKey = mStorageUnit.unwrap(
                        keyRecord.getPrivateKeyData(),
                        pubkey,
                        false,
                        keyRecord.getWrappingParams(mKRA.getStorageKeyUnit().getOldWrappingParams()));
            } catch (Exception e) {
                mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PRIVATE_KEY_NOT_FOUND"));
                throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1",
                        "private key unwrapping failure"), e);
            }
            if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
                mStorageUnit.logout();
            }
            return privKey;
        } catch (Exception e) {
            CMS.debug("RecoverService: recoverKey() failed with allowEncDecrypt_recovery=false:" + e.toString());
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1",
                    "recoverKey() failed with allowEncDecrypt_recovery=false:" + e.toString()));
        }
    }

    /**
     * Creates a PFX (PKCS12) file. (the unwrapping/wrapping way)
     * - used when allowEncDecrypt_recovery is false
     *
     * @param request CRMF recovery request
     * @param priKey private key handle
     * @exception EBaseException failed to create P12 file
     */
    public void createPFX(IRequest request, Hashtable<String, Object> params,
            PrivateKey priKey, CryptoToken ct) throws EBaseException {
        CMS.debug("RecoverService: createPFX() allowEncDecrypt_recovery=false");
        try {
            // create p12
            X509Certificate x509cert =
                    request.getExtDataInCert(ATTR_USER_CERT);
            if (x509cert == null) {
                throw new EKRAException(CMS.getUserMessage("CMS_KRA_PKCS12_FAILED_1","Missing Certificate"));
            }
            String pwd = (String) params.get(ATTR_TRANSPORT_PWD);

            // add certificate
            mKRA.log(ILogger.LL_INFO, "KRA adds certificate to P12");
            CMS.debug("RecoverService: createPFX() adds certificate to P12");
            SEQUENCE encSafeContents = new SEQUENCE();
            ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
            String nickname = request.getExtDataInString(ATTR_NICKNAME);

            if (nickname == null) {
                nickname = x509cert.getSubjectDN().toString();
            }
            byte localKeyId[] = createLocalKeyId(x509cert);
            SET certAttrs = createBagAttrs(
                    nickname, localKeyId);
            // attributes: user friendly name, Local Key ID
            SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
                    new CertBag(CertBag.X509_CERT_TYPE, cert),
                    certAttrs);

            encSafeContents.addElement(certBag);

            // add key
            mKRA.log(ILogger.LL_INFO, "KRA adds key to P12");
            CMS.debug("RecoverService: createPFX() adds key to P12");
            org.mozilla.jss.util.Password pass = new
                    org.mozilla.jss.util.Password(
                            pwd.toCharArray());

            SEQUENCE safeContents = new SEQUENCE();
            PasswordConverter passConverter = new
                    PasswordConverter();
            Random ran = new SecureRandom();
            byte[] salt = new byte[20];
            ran.nextBytes(salt);

            ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
                    PBEAlgorithm.PBE_SHA1_DES3_CBC,
                    pass, salt, 1, passConverter, priKey, ct);
            CMS.debug("RecoverService: createPFX() EncryptedPrivateKeyInfo.createPBE() returned");
            if (key == null) {
                CMS.debug("RecoverService: createPFX() key null");
                throw new EBaseException("EncryptedPrivateKeyInfo.createPBE() failed");
            } else {
                CMS.debug("RecoverService: createPFX() key not null");
            }

            SET keyAttrs = createBagAttrs(
                    x509cert.getSubjectDN().toString(),
                    localKeyId);

            SafeBag keyBag = new SafeBag(
                    SafeBag.PKCS8_SHROUDED_KEY_BAG, key,
                    keyAttrs); // ??

            safeContents.addElement(keyBag);

            // build contents
            AuthenticatedSafes authSafes = new
                    AuthenticatedSafes();

            authSafes.addSafeContents(
                    safeContents
                    );
            authSafes.addSafeContents(
                    encSafeContents
                    );

            //			authSafes.addEncryptedSafeContents(
            //				authSafes.DEFAULT_KEY_GEN_ALG,
            //				pass, null, 1,
            //				encSafeContents);
            PFX pfx = new PFX(authSafes);

            pfx.computeMacData(pass, null, 5); // ??
            ByteArrayOutputStream fos = new
                    ByteArrayOutputStream();

            pfx.encode(fos);
            pass.clear();

            // put final PKCS12 into volatile request
            params.put(ATTR_PKCS12, fos.toByteArray());
            CMS.debug("RecoverService: createPFX() completed.");
        } catch (Exception e) {
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_CONSTRUCT_P12", e.toString()));
            CMS.debug("RecoverService: createPFX() exception caught:"+
                e.toString());
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_PKCS12_FAILED_1", e.toString()));
        }

        // update request
        mKRA.getRequestQueue().updateRequest(request);
    }

    /**
     * Recovers key.
     * - used when allowEncDecrypt_recovery is true
     */
    public synchronized byte[] recoverKey(Hashtable<String, Object> request, KeyRecord keyRecord)
            throws EBaseException {
        if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
            Credential creds[] = (Credential[])
                    request.get(ATTR_AGENT_CREDENTIALS);

            mStorageUnit.login(creds);
        }
        mKRA.log(ILogger.LL_INFO, "KRA decrypts internal private");

        try {
             byte[] privateKeyData = mStorageUnit.decryptInternalPrivate(
                     keyRecord.getPrivateKeyData(),
                     keyRecord.getWrappingParams(mKRA.getStorageKeyUnit().getOldWrappingParams()));

             if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
                 mStorageUnit.logout();
             }

             return privateKeyData;
        } catch (Exception e) {
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PRIVATE_KEY_NOT_FOUND"));
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1", "no private key"));
        }
    }

    /**
     * Creates a PFX (PKCS12) file.
     * - used when allowEncDecrypt_recovery is true
     *
     * @param request CRMF recovery request
     * @param priData decrypted private key (PrivateKeyInfo)
     * @exception EBaseException failed to create P12 file
     */
    public void createPFX(IRequest request, Hashtable<String, Object> params,
            byte priData[]) throws EBaseException {
        CMS.debug("RecoverService: createPFX() allowEncDecrypt_recovery=true");
        try {
            // create p12
            X509Certificate x509cert =
                    request.getExtDataInCert(ATTR_USER_CERT);
            if (x509cert == null) {
                throw new EKRAException(CMS.getUserMessage("CMS_KRA_PKCS12_FAILED_1","Missing Certificate"));
            }
            String pwd = (String) params.get(ATTR_TRANSPORT_PWD);

            // add certificate
            mKRA.log(ILogger.LL_INFO, "KRA adds certificate to P12");
            SEQUENCE encSafeContents = new SEQUENCE();
            ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
            String nickname = request.getExtDataInString(ATTR_NICKNAME);

            if (nickname == null) {
                nickname = x509cert.getSubjectDN().toString();
            }
            byte localKeyId[] = createLocalKeyId(x509cert);
            SET certAttrs = createBagAttrs(
                    nickname, localKeyId);
            // attributes: user friendly name, Local Key ID
            SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
                    new CertBag(CertBag.X509_CERT_TYPE, cert),
                    certAttrs);

            encSafeContents.addElement(certBag);

            // add key
            mKRA.log(ILogger.LL_INFO, "KRA adds key to P12");
            org.mozilla.jss.util.Password pass = new
                    org.mozilla.jss.util.Password(
                            pwd.toCharArray());

            SEQUENCE safeContents = new SEQUENCE();
            PasswordConverter passConverter = new
                    PasswordConverter();
            byte salt[] = { 0x01, 0x01, 0x01, 0x01 };
            PrivateKeyInfo pki = (PrivateKeyInfo)
                    ASN1Util.decode(PrivateKeyInfo.getTemplate(),
                            priData);
            ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
                    PBEAlgorithm.PBE_SHA1_DES3_CBC,
                    pass, salt, 1, passConverter, pki);
            SET keyAttrs = createBagAttrs(
                    x509cert.getSubjectDN().toString(),
                    localKeyId);
            SafeBag keyBag = new SafeBag(
                    SafeBag.PKCS8_SHROUDED_KEY_BAG, key,
                    keyAttrs); // ??

            safeContents.addElement(keyBag);

            // build contents
            AuthenticatedSafes authSafes = new
                    AuthenticatedSafes();

            authSafes.addSafeContents(
                    safeContents
                    );
            authSafes.addSafeContents(
                    encSafeContents
                    );

            //			authSafes.addEncryptedSafeContents(
            //				authSafes.DEFAULT_KEY_GEN_ALG,
            //				pass, null, 1,
            //				encSafeContents);
            PFX pfx = new PFX(authSafes);

            pfx.computeMacData(pass, null, 5); // ??
            ByteArrayOutputStream fos = new
                    ByteArrayOutputStream();

            pfx.encode(fos);
            pass.clear();

            // put final PKCS12 into volatile request
            params.put(ATTR_PKCS12, fos.toByteArray());
        } catch (Exception e) {
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_CONSTRUCT_P12", e.toString()));
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_PKCS12_FAILED_1", e.toString()));
        }

        // update request
        mKRA.getRequestQueue().updateRequest(request);
    }

    /**
     * Creates local key identifier.
     */
    public byte[] createLocalKeyId(X509Certificate cert)
            throws EBaseException {
        try {
            // SHA1 hash of the X509Cert der encoding
            byte certDer[] = cert.getEncoded();

            // XXX - should use JSS
            MessageDigest md = MessageDigest.getInstance("SHA");

            md.update(certDer);
            return md.digest();
        } catch (CertificateEncodingException e) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_CREAT_KEY_ID", e.toString()));
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_KEYID_FAILED_1", e.toString()));
        } catch (NoSuchAlgorithmException e) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_CREAT_KEY_ID", e.toString()));
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_KEYID_FAILED_1", e.toString()));
        }
    }

    /**
     * Creates bag attributes.
     */
    public SET createBagAttrs(String nickName, byte localKeyId[])
            throws EBaseException {
        try {
            SET attrs = new SET();
            SEQUENCE nickNameAttr = new SEQUENCE();

            nickNameAttr.addElement(SafeBag.FRIENDLY_NAME);
            SET nickNameSet = new SET();

            nickNameSet.addElement(new BMPString(nickName));
            nickNameAttr.addElement(nickNameSet);
            attrs.addElement(nickNameAttr);
            SEQUENCE localKeyAttr = new SEQUENCE();

            localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);
            SET localKeySet = new SET();

            localKeySet.addElement(new OCTET_STRING(localKeyId));
            localKeyAttr.addElement(localKeySet);
            attrs.addElement(localKeyAttr);
            return attrs;
        } catch (CharConversionException e) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_CREAT_KEY_BAG", e.toString()));
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_KEYBAG_FAILED_1", e.toString()));
        }
    }
}
