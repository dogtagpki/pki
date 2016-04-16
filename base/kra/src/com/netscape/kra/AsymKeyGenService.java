//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2014 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.kra;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmscore.dbs.KeyRecord;

/**
 * Service class to handle asymmetric key generation requests.
 * A new asymmetric key is generated and archived the database as a key record.
 * The private key is wrapped with the storage key and stored in the privateKeyData attribute of the
 * ldap record.
 * The public key is stored in the publicKeyData attribute of the record.
 *
 * @author akoneru
 *
 */
public class AsymKeyGenService implements IService {

    private static final String ATTR_KEY_RECORD = "keyRecord";
    private static final String STATUS_ACTIVE = "active";

    private IKeyRecoveryAuthority kra = null;
    private IStorageKeyUnit storageUnit = null;
    private ILogger signedAuditLogger = CMS.getSignedAuditLogger();
    private final static String LOGGING_SIGNED_AUDIT_ASYMKEY_GEN_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_ASYMKEY_GEN_REQUEST_PROCESSED_6";

    public AsymKeyGenService(IKeyRecoveryAuthority kra) {
        this.kra = kra;
        this.storageUnit = kra.getStorageKeyUnit();
    }

    @Override
    public boolean serviceRequest(IRequest request) throws EBaseException {

        String clientKeyId = request.getExtDataInString(IRequest.SECURITY_DATA_CLIENT_KEY_ID);
        String algorithm = request.getExtDataInString(IRequest.KEY_GEN_ALGORITHM);

        String keySizeStr = request.getExtDataInString(IRequest.KEY_GEN_SIZE);
        int keySize = Integer.valueOf(keySizeStr);

        String realm = request.getRealm();

        KeyPairGeneratorSpi.Usage[] usageList = null;
        String usageStr = request.getExtDataInString(IRequest.KEY_GEN_USAGES);
        if (usageStr != null) {
            String[] usages = usageStr.split(",");

            if (usages.length > 0) {
                usageList = new KeyPairGeneratorSpi.Usage[usages.length];
                for (int i = 0; i < usages.length; i++) {
                    switch (usages[i]) {
                    case AsymKeyGenerationRequest.DECRYPT:
                        usageList[i] = KeyPairGeneratorSpi.Usage.DECRYPT;
                        break;
                    case AsymKeyGenerationRequest.ENCRYPT:
                        usageList[i] = KeyPairGeneratorSpi.Usage.ENCRYPT;
                        break;
                    case AsymKeyGenerationRequest.WRAP:
                        usageList[i] = KeyPairGeneratorSpi.Usage.WRAP;
                        break;
                    case AsymKeyGenerationRequest.UNWRAP:
                        usageList[i] = KeyPairGeneratorSpi.Usage.UNWRAP;
                        break;
                    case AsymKeyGenerationRequest.DERIVE:
                        usageList[i] = KeyPairGeneratorSpi.Usage.DERIVE;
                        break;
                    case AsymKeyGenerationRequest.SIGN:
                        usageList[i] = KeyPairGeneratorSpi.Usage.SIGN;
                        break;
                    case AsymKeyGenerationRequest.SIGN_RECOVER:
                        usageList[i] = KeyPairGeneratorSpi.Usage.SIGN_RECOVER;
                        break;
                    case AsymKeyGenerationRequest.VERIFY:
                        usageList[i] = KeyPairGeneratorSpi.Usage.VERIFY;
                        break;
                    case AsymKeyGenerationRequest.VERIFY_RECOVER:
                        usageList[i] = KeyPairGeneratorSpi.Usage.VERIFY_RECOVER;
                        break;
                    }
                }
            } else {
                usageList = new KeyPairGeneratorSpi.Usage[2];
                usageList[0] = KeyPairGeneratorSpi.Usage.DECRYPT;
                usageList[1] = KeyPairGeneratorSpi.Usage.ENCRYPT;
            }
        }

        CMS.debug("AsymKeyGenService.serviceRequest. Request id: " + request.getRequestId());
        CMS.debug("AsymKeyGenService.serviceRequest algorithm: " + algorithm);

        KeyPairAlgorithm keyPairAlgorithm = KeyRequestDAO.ASYMKEY_GEN_ALGORITHMS.get(algorithm.toUpperCase());

        String owner = request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER);
        String auditSubjectID = owner;

        // Get the token
        CryptoToken token = kra.getKeygenToken();

        // Generating the asymmetric keys
        KeyPairGenerator keyPairGen = null;
        KeyPair kp = null;

        try {
            keyPairGen = token.getKeyPairGenerator(keyPairAlgorithm);
            keyPairGen.initialize(keySize);
            if (usageList != null)
                keyPairGen.setKeyPairUsages(usageList, usageList);
            kp = keyPairGen.genKeyPair();
        } catch (NoSuchAlgorithmException | TokenException e) {
            CMS.debugStackTrace();
            auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to generate Asymmetric key");
            throw new EBaseException("Errors in generating Asymmetric key: " + e);
        }

        KeyRecord record = new KeyRecord(null, kp.getPublic().getEncoded(), storageUnit.wrap((PrivateKey) kp
                .getPrivate()), owner, algorithm, owner);

        IKeyRepository storage = kra.getKeyRepository();
        BigInteger serialNo = storage.getNextSerialNumber();

        if (serialNo == null) {
            kra.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_GET_NEXT_SERIAL"));
            auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to get next Key ID");
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        // Storing the public key and private key.
        record.set(IKeyRecord.ATTR_CLIENT_ID, clientKeyId);
        record.setSerialNumber(serialNo);
        record.set(KeyRecord.ATTR_ID, serialNo);
        record.set(KeyRecord.ATTR_DATA_TYPE, KeyRequestResource.ASYMMETRIC_KEY_TYPE);
        record.set(KeyRecord.ATTR_STATUS, STATUS_ACTIVE);
        record.set(KeyRecord.ATTR_KEY_SIZE, keySize);
        request.setExtData(ATTR_KEY_RECORD, serialNo);

        if (realm != null) {
            record.set(KeyRecord.ATTR_REALM, realm);
        }

        storage.addKeyRecord(record);

        auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.SUCCESS, request.getRequestId(),
                clientKeyId, serialNo.toString(), "None");
        request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        kra.getRequestQueue().updateRequest(request);
        return true;
    }

    private void audit(String msg) {
        if (signedAuditLogger == null)
            return;

        signedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    private void auditAsymKeyGenRequestProcessed(String subjectID, String status, RequestId requestID,
            String clientKeyID,
            String keyID, String reason) {
        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_ASYMKEY_GEN_REQUEST_PROCESSED,
                subjectID,
                status,
                requestID.toString(),
                clientKeyID,
                keyID != null ? keyID : "None",
                reason);
        audit(auditMessage);
    }
}
