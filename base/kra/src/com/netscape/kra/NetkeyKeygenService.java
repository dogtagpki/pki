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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import netscape.security.provider.RSAPublicKey;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
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
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.servlet.key.KeyRecordParser;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.crypto.CryptoUtil;

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
    public final static String ATTR_KEY_RECORD = "keyRecord";
    public final static String ATTR_PROOF_OF_ARCHIVAL =
            "proofOfArchival";

    // private
    private final static String LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_4";
    private final static String LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_PROCESSED_3";
    // these need to be defined in LogMessages_en.properties later when we do this
    private final static String LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST =
            "LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_3";
    private final static String LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_SUCCESS_4";
    private final static String LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_FAILURE_3";
    private final static String LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_SUCCESS_4";
    private final static String LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_FAILURE_4";
    private IKeyRecoveryAuthority mKRA = null;
    private ITransportKeyUnit mTransportUnit = null;
    private IStorageKeyUnit mStorageUnit = null;
    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();

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

    public KeyPair generateKeyPair(
            KeyPairAlgorithm kpAlg, int keySize, String keyCurve, PQGParams pqg)
            throws NoSuchAlgorithmException, TokenException, InvalidAlgorithmParameterException,
            InvalidParameterException, PQGParamGenException {

        CryptoToken token = mKRA.getKeygenToken();

        CMS.debug("NetkeyKeygenService: key pair is to be generated on slot: " + token.getName());

        /*
           make it temporary so can work with HSM
           netHSM works with
              temporary == true
              sensitive == <do not specify>
              extractable == <do not specify>
           LunaSA2 works with
              temporary == true
              sensitive == true
              extractable == true
        */
        KeyPairGenerator kpGen = token.getKeyPairGenerator(kpAlg);
        IConfigStore config = CMS.getConfigStore();
        IConfigStore kgConfig = config.getSubStore("kra.keygen");
        boolean tp = false;
        boolean sp = false;
        boolean ep = false;
        if ((kgConfig != null) && (!kgConfig.equals(""))) {
            try {
                tp = kgConfig.getBoolean("temporaryPairs", false);
                sp = kgConfig.getBoolean("sensitivePairs", false);
                ep = kgConfig.getBoolean("extractablePairs", false);
                CMS.debug("NetkeyKeygenService: found config store: kra.keygen");
                // by default, let nethsm work
                if ((tp == false) && (sp == false) && (ep == false)) {
                    if (kpAlg == KeyPairAlgorithm.EC) {
                        // set to what works for nethsm
                        tp = true;
                        sp = false;
                        ep = true;
                    } else
                        tp = true;
                    }
            } catch (Exception e) {
                CMS.debug("NetkeyKeygenService: kgConfig.getBoolean failed");
                // by default, let nethsm work
                tp = true;
            }
        } else {
            // by default, let nethsm work
            CMS.debug("NetkeyKeygenService: cannot find config store: kra.keygen, assume temporaryPairs==true");
            if (kpAlg == KeyPairAlgorithm.EC) {
                // set to what works for nethsm
                tp = true;
                sp = false;
                ep = true;
            } else {
                tp = true;
            }
        }

        if (kpAlg == KeyPairAlgorithm.EC) {

            boolean isECDHE = false;
            KeyPair pair = null;

            // used with isECDHE == true
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask_ECDSA[] = {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
            };

            // used with isECDHE == false
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask_ECDH[] = {
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
            };

            try {
                pair = CryptoUtil.generateECCKeyPair(token.getName(),
                    keyCurve /*ECC_curve default*/,
                    null,
                    (isECDHE==true) ? usages_mask_ECDSA: usages_mask_ECDH,
                    tp /*temporary*/, sp? 1:0 /*sensitive*/, ep? 1:0 /*extractable*/);
                CMS.debug("NetkeyKeygenService: after key pair generation" );
            } catch (Exception e) {
                CMS.debug("NetkeyKeygenService: key pair generation with exception:"+e.toString());
            }
            return pair;

        } else { // !EC
            //only specified to "true" will it be set
            if (tp == true) {
                CMS.debug("NetkeyKeygenService: setting temporaryPairs to true");
                kpGen.temporaryPairs(true);
            }

            if (sp == true) {
                CMS.debug("NetkeyKeygenService: setting sensitivePairs to true");
                kpGen.sensitivePairs(true);
            }

            if (ep == true) {
                CMS.debug("NetkeyKeygenService: setting extractablePairs to true");
                kpGen.extractablePairs(true);
            }

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
                KeyPair kp = null;
                synchronized (new Object()) {
                    CMS.debug("NetkeyKeygenService: key pair generation begins");
                    kp = kpGen.genKeyPair();
                    CMS.debug("NetkeyKeygenService: key pair generation done");
                    mKRA.addEntropy(true);
                }
                return kp;
            } else {
                // DSA
                KeyPair kp = null;

                /* no DSA for now... netkey prototype
                do {
                    // 602548 NSS bug - to overcome it, we use isBadDSAKeyPair
                    kp = kpGen.genKeyPair();
                }
                while (isBadDSAKeyPair(kp));
                */
                return kp;
            }
        }
    }

    public KeyPair generateKeyPair(String alg,
            int keySize, String keyCurve,  PQGParams pqg) throws EBaseException {

        KeyPairAlgorithm kpAlg = null;

        if (alg.equals("RSA"))
            kpAlg = KeyPairAlgorithm.RSA;
        else if (alg.equals("EC"))
            kpAlg = KeyPairAlgorithm.EC;
        else
            kpAlg = KeyPairAlgorithm.DSA;

        try {
            KeyPair kp = generateKeyPair(kpAlg, keySize, keyCurve, pqg);

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

    // this encrypts bytes with a symmetric key
    public byte[] encryptIt(byte[] toBeEncrypted, SymmetricKey symKey, CryptoToken token,
                IVParameterSpec IV) {
        try {
            Cipher cipher = token.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD);

            cipher.initEncrypt(symKey, IV);
            byte pri[] = cipher.doFinal(toBeEncrypted);
            return pri;
        } catch (Exception e) {
            CMS.debug("NetkeyKeygenService:initEncrypt() threw exception: " + e.toString());
            return null;
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
        String auditMessage = null;
        String auditSubjectID = null;
        String auditArchiveID = ILogger.UNIDENTIFIED;
        byte[] wrapped_des_key;

        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        String iv_s = "";
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(iv);
        } catch (Exception e) {
            CMS.debug("NetkeyKeygenService.serviceRequest:  " + e.toString());
        }

        IVParameterSpec algParam = new IVParameterSpec(iv);

        wrapped_des_key = null;
        boolean archive = true;
        PK11SymKey sk = null;
        byte[] publicKeyData = null;
        ;
        String PubKey = "";

        String id = request.getRequestId().toString();
        if (id != null) {
            auditArchiveID = id.trim();
        }

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

        auditSubjectID = rCUID + ":" + rUserid;

        SessionContext sContext = SessionContext.getContext();
        String agentId = "";
        if (sContext != null) {
            agentId =
                    (String) sContext.get(SessionContext.USER_ID);
        }

        auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST,
                agentId,
                ILogger.SUCCESS,
                auditSubjectID);

        audit(auditMessage);

        String rWrappedDesKeyString = request.getExtDataInString(IRequest.NETKEY_ATTR_DRMTRANS_DES_KEY);
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

            // unwrap the DES key
            sk = (PK11SymKey) mTransportUnit.unwrap_sym(wrapped_des_key);

            /* XXX could be done in HSM*/
            KeyPair keypair = null;

            CMS.debug("NetkeyKeygenService: about to generate key pair");

            keypair = generateKeyPair(rKeytype /* rKeytype: "RSA" or "EC" */,
                keysize /*Integer.parseInt(len)*/,
                rKeycurve /* for "EC" only */,
                null /*pqgParams*/);

            if (keypair == null) {
                CMS.debug("NetkeyKeygenService: failed generating key pair for " + rCUID + ":" + rUserid);
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));

                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_FAILURE,
                        agentId,
                        ILogger.FAILURE,
                        auditSubjectID);

                audit(auditMessage);

                return false;
            }
            CMS.debug("NetkeyKeygenService: finished generate key pair for " + rCUID + ":" + rUserid);

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

                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_SUCCESS,
                        agentId,
                        ILogger.SUCCESS,
                        auditSubjectID,
                        PubKey);

                audit(auditMessage);

                //...extract the private key handle (not privatekeydata)
                java.security.PrivateKey privKey =
                        keypair.getPrivate();

                if (privKey == null) {
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    CMS.debug("NetkeyKeygenService: failed getting private key");
                    return false;
                } else {
                    CMS.debug("NetkeyKeygenService: got private key");
                }

                if (sk == null) {
                    CMS.debug("NetkeyKeygenService: no DES key");
                    request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                    return false;
                } else {
                    CMS.debug("NetkeyKeygenService: received DES key");
                }

                // 3 wrapping should be done in HSM
                // wrap private key with DES
                KeyWrapper symWrap =
                        keygenToken.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
                CMS.debug("NetkeyKeygenService: wrapper token=" + keygenToken.getName());
                CMS.debug("NetkeyKeygenService: got key wrapper");

                CMS.debug("NetkeyKeygenService: key transport key is on slot: " + sk.getOwningToken().getName());
                symWrap.initWrap(sk, algParam);
                byte wrapped[] = symWrap.wrap((PrivateKey) privKey);
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
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_FAILURE,
                            agentId,
                            ILogger.FAILURE,
                            auditSubjectID,
                            PubKey);

                    audit(auditMessage);
                    return false;
                } else {
                    request.setExtData("wrappedUserPrivate", wrappedPrivKeyString);
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_SUCCESS,
                            agentId,
                            ILogger.SUCCESS,
                            auditSubjectID,
                            PubKey);

                    audit(auditMessage);
                }

                iv_s = /*base64Encode(iv);*/com.netscape.cmsutil.util.Utils.SpecialEncode(iv);
                request.setExtData("iv_s", iv_s);

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

                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST,
                            agentId,
                            ILogger.SUCCESS,
                            auditSubjectID,
                            auditArchiveID);

                    audit(auditMessage);
                    CMS.debug("KRA encrypts private key to put on internal ldap db");
                    byte privateKeyData[] =
                            mStorageUnit.wrap((org.mozilla.jss.crypto.PrivateKey) privKey);

                    if (privateKeyData == null) {
                        request.setExtData(IRequest.RESULT, Integer.valueOf(4));
                        CMS.debug("NetkeyKeygenService: privatekey encryption by storage unit failed");
                        return false;
                    } else
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
                            CMS.debug("NetkeyKeygenService: failed:InvalidKeyException");
                            return false;
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
                                    oidDescription = CMS.BtoA(curveTS);
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
                        CMS.debug("NetkeyKeygenService: serialNo null");
                        return false;
                    }
                    CMS.debug("NetkeyKeygenService: before addKeyRecord");
                    rec.set(KeyRecord.ATTR_ID, serialNo);
                    request.setExtData(ATTR_KEY_RECORD, serialNo);
                    storage.addKeyRecord(rec);
                    CMS.debug("NetkeyKeygenService: key archived for " + rCUID + ":" + rUserid);

                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_PROCESSED,
                            agentId,
                            ILogger.SUCCESS,
                            PubKey);

                    audit(auditMessage);

                } //if archive

                request.setExtData(IRequest.RESULT, Integer.valueOf(1));
            } catch (Exception e) {
                CMS.debug("NetKeyKeygenService: " + e.toString());
                Debug.printStackTrace(e);
                request.setExtData(IRequest.RESULT, Integer.valueOf(4));
            }
        } else
            request.setExtData(IRequest.RESULT, Integer.valueOf(2));

        return true;
    } //serviceRequest

    /**
     * Signed Audit Log
     * y
     * This method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    private void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }
}
