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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.util.Base64OutputStream;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.SecurityDataArchivalProcessedEvent;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.logging.event.SecurityDataExportEvent;
import com.netscape.certsrv.logging.event.ServerSideKeyGenEvent;
import com.netscape.certsrv.logging.event.ServerSideKeyGenProcessedEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.servlet.key.KeyRecordParser;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

import netscape.security.provider.RSAPublicKey;
import netscape.security.util.WrappingParams;

/**
 * A class representing keygen/archival request procesor for requests
 * from netkey RAs.
 * the user private key of the encryption cert is wrapped with a
 * session symmetric key. The session symmetric key is wrapped with the
 * storage key and stored in the internal database for long term
 * storage.
 * The user private key of the encryption cert is to be wrapped with the
 * DES key which came in in the request wrapped with the KRA
 * transport cert. The wrapped user private key is then sent back to
 * the caller (netkey RA) ...netkey RA should already has kek-wrapped
 * des key from the TKS. They are to be sent together back to
 * the token.
 *
 * @author Christina Fu (cfu)
 * @version $Revision$, $Date$
 */

public class NetkeyKeygenService implements IService {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public final static String ATTR_KEY_RECORD = "keyRecord";
    public final static String ATTR_PROOF_OF_ARCHIVAL =
            "proofOfArchival";

    private IKeyRecoveryAuthority mKRA = null;
    private ITransportKeyUnit mTransportUnit = null;
    private IStorageKeyUnit mStorageUnit = null;

    /**
     * Constructs request processor.
     * <P>
     *
     * @param kra key recovery authority
     */
    public NetkeyKeygenService(IKeyRecoveryAuthority kra) {
        mKRA = kra;
        mTransportUnit = kra.getTransportKeyUnit();
        mStorageUnit = kra.getStorageKeyUnit();
    }

    public PKIArchiveOptions toPKIArchiveOptions(byte options[]) {
        ByteArrayInputStream bis = new ByteArrayInputStream(options);
        PKIArchiveOptions archOpts = null;

        try {
            archOpts = (PKIArchiveOptions)
                    (new PKIArchiveOptions.Template()).decode(bis);
        } catch (Exception e) {
            CMS.debug("NetkeyKeygenService: getPKIArchiveOptions " + e.toString());
        }
        return archOpts;
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
     * Services an archival request from netkey.
     * <P>
     *
     * @param request enrollment request
     * @return serving successful or not
     * @exception EBaseException failed to serve
     */
    public boolean serviceRequest(IRequest request)
            throws EBaseException {
        String auditSubjectID = null;
        byte[] wrapped_des_key;

        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        String iv_s = "";
        try {
            JssSubsystem jssSubsystem = (JssSubsystem) CMS.getSubsystem(JssSubsystem.ID);
            SecureRandom random = jssSubsystem.getRandomNumberGenerator();
            random.nextBytes(iv);
        } catch (Exception e) {
            CMS.debug("NetkeyKeygenService.serviceRequest:  " + e.toString());
            throw new EBaseException(e);
        }

        IVParameterSpec algParam = new IVParameterSpec(iv);

        IConfigStore configStore = CMS.getConfigStore();
        boolean allowEncDecrypt_archival = configStore.getBoolean("kra.allowEncDecrypt.archival", false);

        wrapped_des_key = null;
        boolean archive = true;
        byte[] publicKeyData = null;
        ;
        String PubKey = "";

        String rArchive = request.getExtDataInString(IRequest.NETKEY_ATTR_ARCHIVE_FLAG);
        if (rArchive.equals("true")) {
            archive = true;
            CMS.debug("NetkeyKeygenService: serviceRequest " + "archival requested for serverSideKeyGen");
        } else {
            archive = false;
            CMS.debug("NetkeyKeygenService: serviceRequest " + "archival not requested for serverSideKeyGen");
        }

        String rCUID = request.getExtDataInString(IRequest.NETKEY_ATTR_CUID);
        String rUserid = request.getExtDataInString(IRequest.NETKEY_ATTR_USERID);
        String rKeytype = request.getExtDataInString(IRequest.NETKEY_ATTR_KEY_TYPE);
        RequestId requestId = request.getRequestId();

        auditSubjectID = rCUID + ":" + rUserid;

        SessionContext sContext = SessionContext.getContext();
        String agentId = "";
        if (sContext != null) {
            agentId = (String) sContext.get(SessionContext.USER_ID);
        }

        audit(new ServerSideKeyGenEvent(
                agentId,
                ILogger.SUCCESS,
                auditSubjectID,
                requestId));

        String rWrappedDesKeyString = request.getExtDataInString(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY);
        // the request reocrd field delayLDAPCommit == "true" will cause
        // updateRequest() to delay actual write to ldap
        request.setExtData("delayLDAPCommit", "true");
        // wrappedDesKey no longer needed. removing.
        request.setExtData(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY, "");

        //        CMS.debug("NetkeyKeygenService: received DRM-trans-wrapped DES key ="+rWrappedDesKeyString);
        wrapped_des_key = com.netscape.cmsutil.util.Utils.SpecialDecode(rWrappedDesKeyString);
        CMS.debug("NetkeyKeygenService: wrapped_des_key specialDecoded");


        if ((rKeytype == null) || (rKeytype.equals(""))) {
            CMS.debug("NetkeyKeygenService: serviceRequest: key type is null");
            rKeytype = "RSA";
        } else
            CMS.debug("NetkeyKeygenService: serviceRequest: key type = "+ rKeytype);

        /* for EC, keysize is ignored, only key curve is used */
        String rKeysize = "2048";
        int keysize = 2048;
        String rKeycurve = "nistp256";
        if (rKeytype.equals("EC")) {
            rKeycurve = request.getExtDataInString(IRequest.NETKEY_ATTR_KEY_EC_CURVE);
            if ((rKeycurve == null) || (rKeycurve.equals(""))) {
                rKeycurve = "nistp256";
            }
        } else {
            rKeysize = request.getExtDataInString(IRequest.NETKEY_ATTR_KEY_SIZE);
            keysize = Integer.parseInt(rKeysize);
        }

        // get the token for generating user keys
        CryptoToken keygenToken = mKRA.getKeygenToken();
        if (keygenToken == null) {
            CMS.debug("NetkeyKeygenService: failed getting keygenToken");
            request.setExtData(IRequest.RESULT, Integer.valueOf(10));
            return false;
        } else
            CMS.debug("NetkeyKeygenService: got keygenToken");

        if ((wrapped_des_key != null) &&
                (wrapped_des_key.length > 0)) {

            WrappingParams wrapParams = new WrappingParams(
                    SymmetricKey.DES3, KeyGenAlgorithm.DES3, 0,
                    KeyWrapAlgorithm.RSA, EncryptionAlgorithm.DES3_CBC_PAD,
                    KeyWrapAlgorithm.DES3_CBC_PAD, EncryptionUnit.IV, EncryptionUnit.IV);

            /* XXX could be done in HSM*/
            KeyPair keypair = null;

            CMS.debug("NetkeyKeygenService: about to generate key pair");

            keypair = mKRA.generateKeyPair(rKeytype /* rKeytype: "RSA" or "EC" */,
                keysize /*Integer.parseInt(len)*/,
                rKeycurve /* for "EC" only */,
                null /*pqgParams*/,
                null /* usageList*/);

            if (keypair == null) {
                CMS.debug("NetkeyKeygenService: failed generating key pair for " + rCUID + ":" + rUserid);
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));

                audit(new ServerSideKeyGenProcessedEvent(
                        agentId,
                        ILogger.FAILURE,
                        auditSubjectID,
                        requestId,
                        null));

                return false;
            }

            CMS.debug("NetkeyKeygenService: finished generate key pair for " + rCUID + ":" + rUserid);

            java.security.PrivateKey privKey;
            try {
                publicKeyData = keypair.getPublic().getEncoded();
                if (publicKeyData == null) {
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    CMS.debug("NetkeyKeygenService: failed getting publickey encoded");
                    return false;
                } else {
                    //CMS.debug("NetkeyKeygenService: public key binary length ="+ publicKeyData.length);
                    if (rKeytype.equals("EC")) {
                        /* url encode */
                        PubKey = com.netscape.cmsutil.util.Utils.SpecialEncode(publicKeyData);
                        CMS.debug("NetkeyKeygenService: EC PubKey special encoded");
                    } else {
                        PubKey = base64Encode(publicKeyData);
                    }

                    //CMS.debug("NetkeyKeygenService: public key length =" + PubKey.length());
                    request.setExtData("public_key", PubKey);
                }

                audit(new ServerSideKeyGenProcessedEvent(
                        agentId,
                        ILogger.SUCCESS,
                        auditSubjectID,
                        requestId,
                        PubKey));

                //...extract the private key handle (not privatekeydata)
                privKey = keypair.getPrivate();

                if (privKey == null) {
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    CMS.debug("NetkeyKeygenService: failed getting private key");
                    return false;
                } else {
                    CMS.debug("NetkeyKeygenService: got private key");
                }

                // unwrap the DES key
                PK11SymKey sk = null;
                try {
                    sk = (PK11SymKey) mTransportUnit.unwrap_sym(wrapped_des_key, wrapParams);
                    CMS.debug("NetkeyKeygenService: received DES key");
                } catch (Exception e) {
                    CMS.debug("NetkeyKeygenService: no DES key: " + e);
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    return false;
                }

                // 3 wrapping should be done in HSM
                // wrap private key with DES
                CMS.debug("NetkeyKeygenService: wrapper token=" + keygenToken.getName());
                CMS.debug("NetkeyKeygenService: key transport key is on slot: " + sk.getOwningToken().getName());

                byte[] wrapped = CryptoUtil.wrapUsingSymmetricKey(
                        keygenToken,
                        sk,
                        (PrivateKey) privKey,
                        algParam,
                        KeyWrapAlgorithm.DES3_CBC_PAD);

                /*
                  CMS.debug("NetkeyKeygenService: wrap called");
                  CMS.debug(wrapped);
                */
                /* This is for using with my decryption tool and ASN1
                   decoder to see if the private key is indeed PKCS#8 format
                   { // cfu debug
                   String oFilePath = "/tmp/wrappedPrivKey.bin";
                   File file = new File(oFilePath);
                   FileOutputStream ostream = new FileOutputStream(oFilePath);
                   ostream.write(wrapped);
                   ostream.close();
                   }
                */
                String wrappedPrivKeyString = /*base64Encode(wrapped);*/
                com.netscape.cmsutil.util.Utils.SpecialEncode(wrapped);
                if (wrappedPrivKeyString == null) {
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    CMS.debug("NetkeyKeygenService: failed generating wrapped private key");
                    audit(new SecurityDataExportEvent(
                            agentId,
                            ILogger.FAILURE,
                            auditSubjectID,
                            null,
                            "NetkeyKeygenService: failed generating wrapped private key",
                            PubKey));

                    return false;
                } else {
                    request.setExtData("wrappedUserPrivate", wrappedPrivKeyString);

                    audit(new SecurityDataExportEvent(
                            agentId,
                            ILogger.SUCCESS,
                            auditSubjectID,
                            null,
                            null,
                            PubKey));
                }

                iv_s = /*base64Encode(iv);*/com.netscape.cmsutil.util.Utils.SpecialEncode(iv);
                request.setExtData("iv_s", iv_s);

            } catch (Exception e) {
                CMS.debug(e);
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                return false;
            }

            try {
                /*
                 * archival - option flag "archive" controllable by the caller - TPS
                 */
                if (archive) {
                    //
                    // privateKeyData ::= SEQUENCE {
                    //                       sessionKey OCTET_STRING,
                    //                       encKey OCTET_STRING,
                    //                    }
                    //
                    //            mKRA.log(ILogger.LL_INFO, "KRA encrypts internal private");

                    audit(SecurityDataArchivalRequestEvent.createSuccessEvent(
                            agentId,
                            auditSubjectID,
                            request.getRequestId(),
                            null));

                    CMS.debug("KRA encrypts private key to put on internal ldap db");
                    byte privateKeyData[] = null;
                    WrappingParams params = null;

                    try {
                        params = mStorageUnit.getWrappingParams(allowEncDecrypt_archival);

                        // In encrypt mode, the recovery side is doing a decrypt() using the
                        // encryption IV.  To be sure this is successful, we will make sure'
                        // the IVs are the same.
                        params.setPayloadEncryptionIV(params.getPayloadWrappingIV());

                        privateKeyData = mStorageUnit.wrap((org.mozilla.jss.crypto.PrivateKey) privKey, params);

                    } catch (Exception e) {
                        request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                        throw new Exception("Unable to wrap private key with storage key", e);
                    }

                    CMS.debug("NetkeyKeygenService: privatekey encryption by storage unit successful");

                    // create key record
                    KeyRecord rec = new KeyRecord(null, publicKeyData,
                            privateKeyData, rCUID + ":" + rUserid,
                            keypair.getPublic().getAlgorithm(),
                            agentId);

                    CMS.debug("NetkeyKeygenService: got key record");

                    if (rKeytype.equals("RSA")) {
                        try {
                            RSAPublicKey rsaPublicKey = new RSAPublicKey(publicKeyData);
                            rec.setKeySize(Integer.valueOf(rsaPublicKey.getKeySize()));

                        } catch (InvalidKeyException e) {
                            request.setExtData(IRequest.RESULT, Integer.valueOf(11));
                            throw new Exception("Invalid RSA public key", e);
                        }

                    } else if (rKeytype.equals("EC")) {
                        CMS.debug("NetkeyKeygenService: alg is EC");
                        String oidDescription = "UNDETERMINED";
                        // for KeyRecordParser
                        MetaInfo metaInfo = new MetaInfo();

                        try {
                            byte curve[] =
                            ASN1Util.getECCurveBytesByX509PublicKeyBytes(publicKeyData,
                                false /* without tag and size */);
                            if (curve.length != 0) {
                                oidDescription = ASN1Util.getOIDdescription(curve);
                            } else {
                                /* this is to be used by derdump */
                                byte curveTS[] =
                                  ASN1Util.getECCurveBytesByX509PublicKeyBytes(publicKeyData,
                                      true /* with tag and size */);
                                if (curveTS.length != 0) {
                                    oidDescription = Utils.base64encode(curveTS, true);
                                }
                            }
                        } catch (Exception e) {
                            CMS.debug("NetkeyKeygenService: ASN1Util.getECCurveBytesByX509PublicKeyByte() throws exception: "+ e.toString());
                            CMS.debug("NetkeyKeygenService: exception allowed. continue");
                        }

                        metaInfo.set(KeyRecordParser.OUT_KEY_EC_CURVE,
                            oidDescription);

                        rec.set(IKeyRecord.ATTR_META_INFO, metaInfo);
                        // key size does not apply to EC;
                        rec.setKeySize(-1);
                    }

                    //??
                    IKeyRepository storage = mKRA.getKeyRepository();
                    BigInteger serialNo = storage.getNextSerialNumber();

                    if (serialNo == null) {
                        request.setExtData(IRequest.RESULT, Integer.valueOf(11));
                        throw new Exception("Unable to generate next serial number");
                    }

                    rec.setWrappingParams(params, allowEncDecrypt_archival);

                    CMS.debug("NetkeyKeygenService: before addKeyRecord");
                    rec.set(KeyRecord.ATTR_ID, serialNo);
                    request.setExtData(ATTR_KEY_RECORD, serialNo);
                    storage.addKeyRecord(rec);
                    CMS.debug("NetkeyKeygenService: key archived for " + rCUID + ":" + rUserid);

                    audit(SecurityDataArchivalProcessedEvent.createSuccessEvent(
                            agentId,
                            auditSubjectID,
                            request.getRequestId(),
                            null,
                            new KeyId(serialNo),
                            PubKey));
                } //if archive

                request.setExtData(IRequest.RESULT, Integer.valueOf(1));

            } catch (Exception e) {
                CMS.debug(e);

                audit(SecurityDataArchivalProcessedEvent.createFailureEvent(
                        agentId,
                        auditSubjectID,
                        request.getRequestId(),
                        null,
                        null,
                        e.toString(),
                        PubKey));

                Integer result = request.getExtDataInInteger(IRequest.RESULT);
                if (result == null) {
                    // set default RESULT code
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                }

                return false;
            }

        } else
            request.setExtData(IRequest.RESULT, Integer.valueOf(2));

        return true;
    } //serviceRequest

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }
}
