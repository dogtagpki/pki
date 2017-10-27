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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Hashtable;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.PrivateKey.Type;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.util.Base64OutputStream;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.kra.EKRAException;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryProcessedEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Cert;

import netscape.security.util.BigInt;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerValue;
import netscape.security.util.WrappingParams;
import netscape.security.x509.X509Key;

/**
 * A class represents recovery request processor.
 *
 * @author Christina Fu (cfu)
 * @version $Revision$, $Date$
 */
public class TokenKeyRecoveryService implements IService {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String ATTR_NICKNAME = "nickname";
    public static final String ATTR_OWNER_NAME = "ownerName";
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
    private ITransportKeyUnit mTransportUnit = null;

    /**
     * Constructs request processor.
     */
    public TokenKeyRecoveryService(IKeyRecoveryAuthority kra) {
        mKRA = kra;
        mStorage = mKRA.getKeyRepository();
        mStorageUnit = mKRA.getStorageKeyUnit();
        mTransportUnit = kra.getTransportKeyUnit();
    }

    /**
     * Process the HTTP request.
     *
     * @param s The URL to decode
     */
    protected String URLdecode(String s) {
        if (s == null)
            return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());

        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);

            if (c == '+') {
                out.write(' ');
            } else if (c == '%') {
                int c1 = Character.digit(s.charAt(++i), 16);
                int c2 = Character.digit(s.charAt(++i), 16);

                out.write((char) (c1 * 16 + c2));
            } else {
                out.write(c);
            }
        } // end for
        return out.toString();
    }

    public static String normalizeCertStr(String s) {
        StringBuffer val = new StringBuffer();

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\\') {
                i++;
                continue;
            } else if (s.charAt(i) == '\\') {
                i++;
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

    private static String base64Encode(byte[] bytes) throws IOException {
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

    /**
     * Processes a recovery request. The method reads
     * the key record from the database, and tries to recover the
     * key with the storage key unit. Once recovered, it wraps it
     * with desKey
     * In the params
     * - cert is used for recovery record search
     * - cuid may be used for additional validation check
     * - userid may be used for additional validation check
     * - wrappedDesKey is used for wrapping recovered private key
     *
     * @param request recovery request
     * @return operation success or not
     * @exception EBaseException failed to serve
     */
    public synchronized boolean serviceRequest(IRequest request) throws EBaseException {
        String auditSubjectID = null;
        String iv_s = "";

        CMS.debug("KRA services token key recovery request");
        IConfigStore config = null;
        Boolean allowEncDecrypt_recovery = false;

        try {
            config = CMS.getConfigStore();
            allowEncDecrypt_recovery = config.getBoolean("kra.allowEncDecrypt.recovery", false);
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CERT_ERROR", e.toString()));
        }

        byte[] wrapped_des_key;

        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        try {
            JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
            SecureRandom random = jssSubsystem.getRandomNumberGenerator();
            random.nextBytes(iv);
        } catch (Exception e) {
            CMS.debug("TokenKeyRecoveryService.serviceRequest: " + e.toString());
            throw new EBaseException(e);
        }

        RequestId auditRequestID = request.getRequestId();

        SessionContext sContext = SessionContext.getContext();
        String agentId = "";
        if (sContext != null) {
            agentId =
                    (String) sContext.get(SessionContext.USER_ID);
        }

        Hashtable<String, Object> params = mKRA.getVolatileRequest(
                 request.getRequestId());

        if (params == null) {
            // possibly we are in recovery mode
            CMS.debug("getVolatileRequest params null");
            //            return true;
        }

        wrapped_des_key = null;

        PK11SymKey sk = null;

        String rCUID = request.getExtDataInString(IRequest.NETKEY_ATTR_CUID);
        String rUserid = request.getExtDataInString(IRequest.NETKEY_ATTR_USERID);
        String rWrappedDesKeyString = request.getExtDataInString(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY);
        // the request record field delayLDAPCommit == "true" will cause
        // updateRequest() to delay actual write to ldap
        request.setExtData("delayLDAPCommit", "true");
        // wrappedDesKey no longer needed. removing.
        request.setExtData(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY, "");

        auditSubjectID = rCUID + ":" + rUserid;

        //CMS.debug("TokenKeyRecoveryService: received DRM-trans-wrapped des key =" + rWrappedDesKeyString);
        CMS.debug("TokenKeyRecoveryService: received DRM-trans-wrapped des key");
        wrapped_des_key = com.netscape.cmsutil.util.Utils.SpecialDecode(rWrappedDesKeyString);
        CMS.debug("TokenKeyRecoveryService: wrapped_des_key specialDecoded");

        if ((wrapped_des_key != null) &&
                (wrapped_des_key.length > 0)) {

            WrappingParams wrapParams = new WrappingParams(
                    SymmetricKey.DES3, KeyGenAlgorithm.DES3, 0,
                    KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                    KeyWrapAlgorithm.DES3_CBC_PAD, EncryptionUnit.IV, EncryptionUnit.IV);

            // unwrap the des key
            try {
                sk = (PK11SymKey) mTransportUnit.unwrap_sym(wrapped_des_key, wrapParams);
                CMS.debug("TokenKeyRecoveryService: received des key");
            } catch (Exception e) {
                CMS.debug("TokenKeyRecoveryService: no des key");
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));
            }
        } else {
            CMS.debug("TokenKeyRecoveryService: not receive des key");
            request.setExtData(IRequest.RESULT, Integer.valueOf(4));
            audit(new SecurityDataRecoveryProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        null,
                        "TokenRecoveryService: Did not receive DES key",
                        agentId));

            return false;
        }

        // retrieve based on Certificate
        String cert_s = request.getExtDataInString(ATTR_USER_CERT);
        String keyid_s = request.getExtDataInString(IRequest.NETKEY_ATTR_KEYID);
        KeyId keyId = keyid_s != null ? new KeyId(keyid_s): null;
        /* have to have at least one */
        if ((cert_s == null) && (keyid_s == null)) {
            CMS.debug("TokenKeyRecoveryService: not receive cert or keyid");
            request.setExtData(IRequest.RESULT, Integer.valueOf(3));
            audit(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditRequestID,
                    keyId,
                    "TokenRecoveryService: Did not receive cert or keyid",
                    agentId));
            return false;
        }

        String cert = null;
        BigInteger keyid = null;
        java.security.cert.X509Certificate x509cert = null;
        if (keyid_s == null) {
            cert = normalizeCertStr(cert_s);
            try {
                x509cert = Cert.mapCert(cert);
                if (x509cert == null) {
                    CMS.debug("cert mapping failed");
                    request.setExtData(IRequest.RESULT, Integer.valueOf(5));
                    audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequestID,
                            keyId,
                            "TokenRecoveryService: cert mapping failed",
                            agentId));
                    return false;
                }
            } catch (IOException e) {
                CMS.debug("TokenKeyRecoveryService: mapCert failed");
                request.setExtData(IRequest.RESULT, Integer.valueOf(6));
                audit(new SecurityDataRecoveryProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        keyId,
                        "TokenRecoveryService: mapCert failed: " + e.getMessage(),
                        agentId));
                return false;
            }
        } else {
            keyid = new BigInteger(keyid_s);
        }

        try {
            /*
            CryptoToken internalToken =
            CryptoManager.getInstance().getInternalKeyStorageToken();
            */
            CryptoToken token = mStorageUnit.getToken();
            CMS.debug("TokenKeyRecoveryService: got token slot:" + token.getName());
            IVParameterSpec algParam = new IVParameterSpec(iv);

            KeyRecord keyRecord = null;
            CMS.debug("KRA reading key record");
            try {
                if (keyid != null) {
                    CMS.debug("TokenKeyRecoveryService: recover by keyid");
                    keyRecord = (KeyRecord) mStorage.readKeyRecord(keyid);
                } else {
                    CMS.debug("TokenKeyRecoveryService: recover by cert");
                    keyRecord = (KeyRecord) mStorage.readKeyRecord(cert);
                }

                if (keyRecord != null)
                    CMS.debug("read key record");
                else {
                    CMS.debug("key record not found");
                    request.setExtData(IRequest.RESULT, Integer.valueOf(8));
                    audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequestID,
                            keyId,
                            "TokenRecoveryService: key record not found",
                            agentId));
                    return false;
                }
            } catch (Exception e) {
                com.netscape.cmscore.util.Debug.printStackTrace(e);
                request.setExtData(IRequest.RESULT, Integer.valueOf(9));
                audit(new SecurityDataRecoveryProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        keyId,
                        "TokenRecoveryService: error reading key record: " + e.getMessage(),
                        agentId));
                return false;
            }

            // see if the owner name matches (cuid:userid) -XXX need make this optional
            String owner = keyRecord.getOwnerName();
            CMS.debug("TokenKeyRecoveryService: owner name on record =" + owner);
            CMS.debug("TokenKeyRecoveryService: owner name from TPS =" + rCUID + ":" + rUserid);
            if (owner != null) {
                if (owner.equals(rCUID + ":" + rUserid)) {
                    CMS.debug("TokenKeyRecoveryService: owner name matches");
                } else {
                    CMS.debug("TokenKeyRecoveryService: owner name mismatches");
                }
            }

            // see if the certificate matches the key
            byte pubData[] = null;
            pubData = keyRecord.getPublicKeyData();
            // but if search by keyid, did not come with a cert
            // so can't check
            if (keyid == null) {
                // see if the certificate matches the key
                byte inputPubData[] = x509cert.getPublicKey().getEncoded();

                if (inputPubData.length != pubData.length) {
                    mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PUBLIC_KEY_LEN"));
                    audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequestID,
                            keyId,
                            CMS.getLogMessage("CMSCORE_KRA_PUBLIC_KEY_LEN"),
                            agentId));

                    throw new EKRAException(
                            CMS.getUserMessage("CMS_KRA_PUBLIC_KEY_NOT_MATCHED"));
                }

                for (int i = 0; i < pubData.length; i++) {
                    if (pubData[i] != inputPubData[i]) {
                        mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PUBLIC_KEY_LEN"));
                        audit(new SecurityDataRecoveryProcessedEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequestID,
                                keyId,
                                CMS.getLogMessage("CMSCORE_KRA_PUBLIC_KEY_LEN"),
                                agentId));
                        throw new EKRAException(
                                CMS.getUserMessage("CMS_KRA_PUBLIC_KEY_NOT_MATCHED"));
                    }
                }
            } // else, searched by keyid, can't check

            Boolean encrypted = keyRecord.isEncrypted();
            if (encrypted == null) {
                // must be an old key record
                // assume the value of allowEncDecrypt
                encrypted = allowEncDecrypt_recovery;
            }

            Type keyType = PrivateKey.RSA;
            byte wrapped[];
            if (encrypted) {
                // Unwrap the archived private key
                byte privateKeyData[] = null;
                privateKeyData = recoverKey(params, keyRecord);
                if (privateKeyData == null) {
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    CMS.debug("TokenKeyRecoveryService: failed getting private key");
                    audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequestID,
                            keyId,
                            "TokenKeyRecoveryService: failed getting private key",
                            agentId));
                    return false;
                }
                CMS.debug("TokenKeyRecoveryService: got private key...about to verify");

                iv_s = /*base64Encode(iv);*/com.netscape.cmsutil.util.Utils.SpecialEncode(iv);
                request.setExtData("iv_s", iv_s);

                CMS.debug("request.setExtData: iv_s: " + iv_s);

                /* LunaSA returns data with padding which we need to remove */
                ByteArrayInputStream dis = new ByteArrayInputStream(privateKeyData);
                DerValue dv = new DerValue(dis);
                byte p[] = dv.toByteArray();
                int l = p.length;
                CMS.debug("length different data length=" + l +
                    " real length=" + privateKeyData.length);
                if (l != privateKeyData.length) {
                    privateKeyData = p;
                }

                if (verifyKeyPair(pubData, privateKeyData) == false) {
                    mKRA.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_KRA_PUBLIC_NOT_FOUND"));
                    audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequestID,
                            keyId,
                            CMS.getLogMessage("CMSCORE_KRA_PUBLIC_NOT_FOUND"),
                            agentId));
                    JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
                    jssSubsystem.obscureBytes(privateKeyData);
                    jssSubsystem.obscureBytes(p);
                    throw new EKRAException(
                        CMS.getUserMessage("CMS_KRA_INVALID_PUBLIC_KEY"));
                } else {
                    CMS.debug("TokenKeyRecoveryService: private key verified with public key");
                }

                //encrypt and put in private key
                wrapped = CryptoUtil.encryptUsingSymmetricKey(
                        token,
                        sk,
                        privateKeyData,
                        EncryptionAlgorithm.DES3_CBC_PAD,
                        algParam);

                JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
                jssSubsystem.obscureBytes(privateKeyData);
                jssSubsystem.obscureBytes(p);
            } else { //encrypted == false
                PrivateKey privKey = recoverKey(params, keyRecord, allowEncDecrypt_recovery);
                if (privKey == null) {
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    CMS.debug("TokenKeyRecoveryService: failed getting private key");
                    audit(new SecurityDataRecoveryProcessedEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequestID,
                            keyId,
                            "TokenKeyRecoveryService: failed getting private key",
                            agentId));
                    return false;
                }

                CMS.debug("TokenKeyRecoveryService: about to wrap...");

                wrapped = CryptoUtil.wrapUsingSymmetricKey(
                        token,
                        sk,
                        privKey,
                        algParam,
                        KeyWrapAlgorithm.DES3_CBC_PAD);

                iv_s = /*base64Encode(iv);*/com.netscape.cmsutil.util.Utils.SpecialEncode(iv);
                request.setExtData("iv_s", iv_s);
            }

            String wrappedPrivKeyString =
                com.netscape.cmsutil.util.Utils.SpecialEncode(wrapped);

            if (wrappedPrivKeyString == null) {
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                CMS.debug("TokenKeyRecoveryService: failed generating wrapped private key");
                audit(new SecurityDataRecoveryProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        keyId,
                        "TokenKeyRecoveryService: failed generating wrapped private key",
                        agentId));
                return false;
            } else {
                CMS.debug("TokenKeyRecoveryService: got private key data wrapped");
                request.setExtData("wrappedUserPrivate",
                        wrappedPrivKeyString);
                request.setExtData(IRequest.RESULT, Integer.valueOf(1));
                CMS.debug("TokenKeyRecoveryService: key for " + rCUID + ":" + rUserid + " recovered");
            }

            //convert and put in the public key
            String PubKey = "";
            if (keyType == PrivateKey.EC) {
                /* url encode */
                PubKey = com.netscape.cmsutil.util.Utils.SpecialEncode(pubData);
                CMS.debug("TokenKeyRecoveryService: EC PubKey special encoded");
            } else {
                PubKey = base64Encode(pubData);
                CMS.debug("TokenKeyRecoveryService: RSA PubKey base64 encoded");
            }

            audit(new SecurityDataRecoveryEvent(
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditRequestID,
                    null,
                    PubKey));

            if (PubKey == null) {
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                CMS.debug("TokenKeyRecoveryService: failed getting publickey encoded");
                audit(new SecurityDataRecoveryProcessedEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditRequestID,
                        keyId,
                        "TokenKeyRecoveryService: failed getting publickey encoded",
                        agentId));
                return false;
            } else {
                //CMS.debug("TokenKeyRecoveryService: got publicKeyData b64 = " +
                //        PubKey);
                CMS.debug("TokenKeyRecoveryService: got publicKeyData");
            }
            request.setExtData("public_key", PubKey);

            audit(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditRequestID,
                    keyId,
                    null,
                    agentId));
            return true;

        } catch (Exception e) {
            CMS.debug(e);
            request.setExtData(IRequest.RESULT, Integer.valueOf(4));
        }

        return true;
    }

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
            BigInt privateKeyVersion = privateKeyDerIn.getInteger(); // consume stream
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
     * Recovers key.
     *     - with allowEncDecrypt_archival == false
     */
    public synchronized PrivateKey recoverKey(Hashtable<String, Object> request, KeyRecord keyRecord, boolean allowEncDecrypt_archival)
        throws EBaseException {
        CMS.debug( "TokenKeyRecoveryService: recoverKey() - with allowEncDecrypt_archival being false");
        if (allowEncDecrypt_archival) {
            CMS.debug( "TokenKeyRecoveryService: recoverKey() - allowEncDecrypt_archival needs to be false for this call");
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1", "recoverKey, allowEncDecrypt_archival needs to be false for this call"));
        }

        try {
            PublicKey pubkey = null;
            try {
                pubkey = X509Key.parsePublicKey (new DerValue(keyRecord.getPublicKeyData()));
            } catch (Exception e) {
                CMS.debug("TokenKeyRecoverService: after parsePublicKey:"+e.toString());
                throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1", "public key parsing failure"));
            }

            PrivateKey privKey = null;
            try {
                privKey = mStorageUnit.unwrap(
                        keyRecord.getPrivateKeyData(),
                        pubkey,
                        false,
                        keyRecord.getWrappingParams(mStorageUnit.getOldWrappingParams()));
            } catch (Exception e) {
                CMS.debug("TokenKeyRecoveryService: recoverKey() - recovery failure");
                throw new EKRAException(
                        CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1",
                                "private key recovery/unwrapping failure"), e);
            }
            CMS.debug( "TokenKeyRecoveryService: recoverKey() - recovery completed, returning privKey");
            return privKey;

        } catch (Exception e) {
            CMS.debug("TokenKeyRecoverService: recoverKey() failed with allowEncDecrypt_recovery=false:"+e.toString());
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1", "Exception:"+e.toString()));
        }
    }
    /**
     * Recovers key.
     */
    public synchronized byte[] recoverKey(Hashtable<String, Object> request, KeyRecord keyRecord)
            throws EBaseException {
        CMS.debug( "TokenKeyRecoveryService: recoverKey() - with allowEncDecrypt_archival being true");
        /*
            Credential creds[] = (Credential[])
                request.get(ATTR_AGENT_CREDENTIALS);

            mStorageUnit.login(creds);
        */
        try {
             return mStorageUnit.decryptInternalPrivate(
                     keyRecord.getPrivateKeyData(),
                     keyRecord.getWrappingParams(mStorageUnit.getOldWrappingParams()));
             /* mStorageUnit.logout();*/
        } catch (Exception e){
            mKRA.log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_KRA_PRIVATE_KEY_NOT_FOUND"));
            throw new EKRAException(CMS.getUserMessage("CMS_KRA_RECOVERY_FAILED_1", "no private key"));
        }
    }

    /**
     * Signed Audit Log
     * y
     * This method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    private void audit(String msg) {
        signedAuditLogger.log(msg);
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }
}
