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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.netscape.security.util.WrappingParams;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.SymKeyGenerationProcessedEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This implementation implements SecurityData archival operations.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class SymKeyGenService implements IService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SymKeyGenService.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public final static String ATTR_KEY_RECORD = "keyRecord";
    private final static String STATUS_ACTIVE = "active";

    private IKeyRecoveryAuthority mKRA = null;
    private IStorageKeyUnit mStorageUnit = null;

    public SymKeyGenService(IKeyRecoveryAuthority kra) {
        mKRA = kra;
        mStorageUnit = kra.getStorageKeyUnit();
    }

    /**
     * Performs the service of archiving Security Data.
     * represented by this request.
     * <p>
     *
     * @param request
     *            The request that needs service. The service may use
     *            attributes stored in the request, and may update the
     *            values, or store new ones.
     * @return
     *         an indication of whether this request is still pending.
     *         'false' means the request will wait for further notification.
     * @exception EBaseException indicates major processing failure.
     */
    public boolean serviceRequest(IRequest request)
            throws EBaseException {
        String id = request.getRequestId().toString();
        String clientKeyId = request.getExtDataInString(IRequest.SECURITY_DATA_CLIENT_KEY_ID);
        String algorithm = request.getExtDataInString(IRequest.KEY_GEN_ALGORITHM);
        String realm = request.getRealm();

        String usageStr = request.getExtDataInString(IRequest.KEY_GEN_USAGES);
        List<String> usages = new ArrayList<String>(
                Arrays.asList(StringUtils.split(usageStr, ",")));

        String keySizeStr = request.getExtDataInString(IRequest.KEY_GEN_SIZE);
        int keySize = Integer.parseInt(keySizeStr);

        logger.debug("SymKeyGenService: request ID: " + id);
        logger.debug("SymKeyGenService: algorithm: " + algorithm);

        String owner = request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER);
        String auditSubjectID = owner;

        //Check here even though restful layer checks for this.
        if (algorithm == null || clientKeyId == null || keySize <= 0) {
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Bad data in request");
            throw new EBaseException("Bad data in SymKeyGenService.serviceRequest");
        }

        CMSEngine engine = CMS.getCMSEngine();
        IConfigStore configStore = engine.getConfigStore();
        boolean allowEncDecrypt_archival = configStore.getBoolean("kra.allowEncDecrypt.archival", false);

        CryptoToken token = mStorageUnit.getToken();
        KeyGenAlgorithm kgAlg = KeyRequestDAO.SYMKEY_GEN_ALGORITHMS.get(algorithm);
        if (kgAlg == null) {
            throw new EBaseException("Invalid algorithm");
        }

        SymmetricKey.Usage keyUsages[];
        if (usages.size() > 0) {
            keyUsages = new SymmetricKey.Usage[usages.size()];
            int index = 0;
            for (String usage : usages) {
                switch (usage) {
                case SymKeyGenerationRequest.DECRYPT_USAGE:
                    keyUsages[index] = SymmetricKey.Usage.DECRYPT;
                    break;
                case SymKeyGenerationRequest.ENCRYPT_USAGE:
                    keyUsages[index] = SymmetricKey.Usage.ENCRYPT;
                    break;
                case SymKeyGenerationRequest.WRAP_USAGE:
                    keyUsages[index] = SymmetricKey.Usage.WRAP;
                    break;
                case SymKeyGenerationRequest.UWRAP_USAGE:
                    keyUsages[index] = SymmetricKey.Usage.UNWRAP;
                    break;
                case SymKeyGenerationRequest.SIGN_USAGE:
                    keyUsages[index] = SymmetricKey.Usage.SIGN;
                    break;
                case SymKeyGenerationRequest.VERIFY_USAGE:
                    keyUsages[index] = SymmetricKey.Usage.VERIFY;
                    break;
                default:
                    throw new EBaseException("Invalid usage");
                }
                index++;
            }
        } else {
            keyUsages = new SymmetricKey.Usage[2];
            keyUsages[0] = SymmetricKey.Usage.DECRYPT;
            keyUsages[1] = SymmetricKey.Usage.ENCRYPT;
        }

        SymmetricKey sk = null;
        try {
            sk = CryptoUtil.generateKey(token, kgAlg, keySize, keyUsages, true);
            logger.debug("SymKeyGenService: session key generated on slot: " + token.getName());
        } catch (Exception e) {
            String message = "Unable to generate symmetric key: " + e.getMessage();
            logger.error("SymKeyGenService: " + message, e);
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, message);
            throw new EBaseException(message, e);
        }

        byte[] publicKey = null;
        byte privateSecurityData[] = null;
        WrappingParams params = null;

        if (sk == null) {
            String message = "Unable to generate security data";
            logger.error("SymKeyGenService: " + message);
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, message);
            throw new EBaseException(message);
        }

        try {
            params = mStorageUnit.getWrappingParams(allowEncDecrypt_archival);
            privateSecurityData = mStorageUnit.wrap(sk, params);
        } catch (Exception e) {
            String message = "Unable to wrap security data: " + e.getMessage();
            logger.error("SymKeyGenService: " + message);
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, message);
            throw new EBaseException(message, e);
        }

        // create key record
        KeyRecord rec = new KeyRecord(null, publicKey,
                privateSecurityData, owner,
                algorithm, owner);

        rec.set(IKeyRecord.ATTR_CLIENT_ID, clientKeyId);

        //Now we need a serial number for our new key.
        if (rec.getSerialNumber() != null) {
            String message = CMS.getUserMessage("CMS_KRA_INVALID_STATE");
            logger.error("SymKeyGenService: " + message);
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, message);
            throw new EBaseException(message);
        }

        IKeyRepository storage = mKRA.getKeyRepository();
        BigInteger serialNo = storage.getNextSerialNumber();

        if (serialNo == null) {
            String message = CMS.getLogMessage("CMSCORE_KRA_GET_NEXT_SERIAL");
            logger.error("SymKeyGenService: " + message);
            mKRA.log(ILogger.LL_FAILURE, message);
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, message);
            throw new EBaseException(message);
        }

        rec.set(KeyRecord.ATTR_ID, serialNo);
        rec.set(KeyRecord.ATTR_DATA_TYPE, KeyRequestResource.SYMMETRIC_KEY_TYPE);
        rec.set(KeyRecord.ATTR_STATUS, STATUS_ACTIVE);
        rec.set(KeyRecord.ATTR_KEY_SIZE, keySize);
        request.setExtData(ATTR_KEY_RECORD, serialNo);

        if (realm != null) {
            rec.set(KeyRecord.ATTR_REALM, realm);
        }

        try {
            rec.setWrappingParams(params, allowEncDecrypt_archival);
        } catch (Exception e) {
            String message = "Unable to store wrapping parameters: " + e.getMessage();
            logger.error("SymKeyGenService: " + message, e);
            mKRA.log(ILogger.LL_FAILURE, message);
            auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, message);
            throw new EBaseException(message, e);
        }

        logger.debug("SymKeyGenService: adding security data key record " + serialNo);
        storage.addKeyRecord(rec);

        auditSymKeyGenRequestProcessed(auditSubjectID, ILogger.SUCCESS, request.getRequestId(),
                clientKeyId, new KeyId(serialNo), "None");

        request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        mKRA.getRequestQueue().updateRequest(request);

        return true;
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }

    private void auditSymKeyGenRequestProcessed(String subjectID, String status, RequestId requestID, String clientKeyID,
            KeyId keyID, String reason) {
        audit(new SymKeyGenerationProcessedEvent(
                subjectID,
                status,
                requestID,
                clientKeyID,
                keyID,
                reason));
    }
}