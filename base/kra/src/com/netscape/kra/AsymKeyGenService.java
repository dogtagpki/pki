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

import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.PrivateKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.AsymKeyGenerationProcessedEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.dbs.KeyRecord;

import netscape.security.util.WrappingParams;

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

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    private static final String ATTR_KEY_RECORD = "keyRecord";
    private static final String STATUS_ACTIVE = "active";

    private IKeyRecoveryAuthority kra = null;
    private IStorageKeyUnit storageUnit = null;

    public AsymKeyGenService(IKeyRecoveryAuthority kra) {
        this.kra = kra;
        this.storageUnit = kra.getStorageKeyUnit();
    }

    @Override
    public boolean serviceRequest(IRequest request) throws EBaseException {
        IConfigStore configStore = CMS.getConfigStore();
        String clientKeyId = request.getExtDataInString(IRequest.SECURITY_DATA_CLIENT_KEY_ID);
        String algorithm = request.getExtDataInString(IRequest.KEY_GEN_ALGORITHM);

        String keySizeStr = request.getExtDataInString(IRequest.KEY_GEN_SIZE);
        int keySize = Integer.valueOf(keySizeStr);

        String realm = request.getRealm();

        boolean allowEncDecrypt_archival = configStore.getBoolean("kra.allowEncDecrypt.archival", false);

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

        String owner = request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER);
        String auditSubjectID = owner;

        // Generating the asymmetric keys
        KeyPair kp = null;

        try {
            kp = kra.generateKeyPair(
                    algorithm.toUpperCase(),
                    keySize,
                    null, // keyCurve for ECC, not yet supported
                    null, // PQG not yet supported
                    usageList
                 );

        } catch (EBaseException e) {
            CMS.debugStackTrace();
            auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to generate asymmetric key: " + e.getMessage());
            throw new EBaseException("Errors in generating Asymmetric key: " + e, e);
        }

        if (kp == null) {
            auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to generate asymmetric key");
            throw new EBaseException("Failed to generate asymmetric key!");
        }

        byte[] privateSecurityData = null;
        WrappingParams params = null;

        try {
            params = storageUnit.getWrappingParams(allowEncDecrypt_archival);
            privateSecurityData = storageUnit.wrap((PrivateKey) kp.getPrivate(), params);
        } catch (Exception e) {
            CMS.debug("Failed to generate security data to archive: " + e);
            auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, CMS.getUserMessage("CMS_KRA_INVALID_PRIVATE_KEY"));
            throw new EBaseException("Failed to generate security data to archive!", e);
        }

        KeyRecord record = new KeyRecord(null, kp.getPublic().getEncoded(), privateSecurityData,
                owner, algorithm, owner);

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

        try {
            record.setWrappingParams(params, allowEncDecrypt_archival);
        } catch (Exception e) {
            auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to store wrapping params");
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        storage.addKeyRecord(record);

        auditAsymKeyGenRequestProcessed(auditSubjectID, ILogger.SUCCESS, request.getRequestId(),
                clientKeyId, new KeyId(serialNo), "None");
        request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        kra.getRequestQueue().updateRequest(request);
        return true;
    }

    private void audit(String msg) {
        signedAuditLogger.log(msg);
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }

    private void auditAsymKeyGenRequestProcessed(String subjectID, String status, RequestId requestID,
            String clientKeyID,
            KeyId keyID, String reason) {
        audit(new AsymKeyGenerationProcessedEvent(
                subjectID,
                status,
                requestID,
                clientKeyID,
                keyID,
                reason));
    }
}
