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

import java.io.CharConversionException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmscore.dbs.KeyRecord;

/**
 * This implementation implements SecurityData archival operations.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class SymKeyGenService implements IService {

    private final static String DEFAULT_OWNER = "IPA Agent";
    public final static String ATTR_KEY_RECORD = "keyRecord";
    private final static String STATUS_ACTIVE = "active";

    private IKeyRecoveryAuthority mKRA = null;
    private IStorageKeyUnit mStorageUnit = null;
    private ILogger signedAuditLogger = CMS.getSignedAuditLogger();

    private final static String LOGGING_SIGNED_AUDIT_SYMKEY_GEN_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_SYMKEY_GEN_REQUEST_PROCESSED_6";

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
        String algorithm = request.getExtDataInString(IRequest.SYMKEY_GEN_ALGORITHM);

        String usageStr = request.getExtDataInString(IRequest.SYMKEY_GEN_USAGES);
        List<String> usages = new ArrayList<String>(
                Arrays.asList(StringUtils.split(usageStr, ",")));

        String keySizeStr = request.getExtDataInString(IRequest.SYMKEY_GEN_SIZE);
        int keySize = Integer.parseInt(keySizeStr);

        CMS.debug("SymKeyGenService.serviceRequest. Request id: " + id);
        CMS.debug("SymKeyGenService.serviceRequest algorithm: " + algorithm);

        String owner = getOwnerName(request);
        String subjectID = auditSubjectID();

        //Check here even though restful layer checks for this.
        if (algorithm == null || clientKeyId == null || keySize <= 0) {
            auditSymKeyGenRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Bad data in request");
            throw new EBaseException("Bad data in SymKeyGenService.serviceRequest");
        }

        CryptoToken token = mStorageUnit.getToken();
        KeyGenAlgorithm kgAlg = KeyRequestDAO.KEYGEN_ALGORITHMS.get(algorithm);
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
            KeyGenerator kg = token.getKeyGenerator(kgAlg);
            kg.setKeyUsages(keyUsages);
            kg.temporaryKeys(true);
            if (kgAlg == KeyGenAlgorithm.AES || kgAlg == KeyGenAlgorithm.RC4
                    || kgAlg == KeyGenAlgorithm.RC2) {
                kg.initialize(keySize);
            }
            sk = kg.generate();
            CMS.debug("SymKeyGenService:wrap() session key generated on slot: " + token.getName());
        } catch (TokenException | IllegalStateException | CharConversionException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException e) {
            CMS.debugStackTrace();
            auditSymKeyGenRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to generate symmetric key");
            throw new EBaseException("Errors in generating symmetric key: " + e);
        }

        byte[] publicKey = null;
        byte privateSecurityData[] = null;

        if (sk != null) {
            privateSecurityData = mStorageUnit.wrap(sk);
        } else { // We have no data.
            auditSymKeyGenRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to create security data to archive");
            throw new EBaseException("Failed to create security data to archive!");
        }

        // create key record
        KeyRecord rec = new KeyRecord(null, publicKey,
                privateSecurityData, owner,
                algorithm, owner);

        rec.set(IKeyRecord.ATTR_CLIENT_ID, clientKeyId);

        //Now we need a serial number for our new key.
        if (rec.getSerialNumber() != null) {
            auditSymKeyGenRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        IKeyRepository storage = mKRA.getKeyRepository();
        BigInteger serialNo = storage.getNextSerialNumber();

        if (serialNo == null) {
            mKRA.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_KRA_GET_NEXT_SERIAL"));
            auditSymKeyGenRequestProcessed(subjectID, ILogger.FAILURE, request.getRequestId(),
                    clientKeyId, null, "Failed to get  next Key ID");
            throw new EBaseException(CMS.getUserMessage("CMS_KRA_INVALID_STATE"));
        }

        rec.set(KeyRecord.ATTR_ID, serialNo);
        rec.set(KeyRecord.ATTR_DATA_TYPE, KeyRequestResource.SYMMETRIC_KEY_TYPE);
        rec.set(KeyRecord.ATTR_STATUS, STATUS_ACTIVE);
        rec.set(KeyRecord.ATTR_ALGORITHM, algorithm);
        rec.set(KeyRecord.ATTR_KEY_SIZE, keySize);
        request.setExtData(ATTR_KEY_RECORD, serialNo);

        CMS.debug("KRA adding Security Data key record " + serialNo);
        storage.addKeyRecord(rec);

        auditSymKeyGenRequestProcessed(subjectID, ILogger.SUCCESS, request.getRequestId(),
                clientKeyId, serialNo.toString(), "None");

        request.setExtData(IRequest.RESULT, IRequest.RES_SUCCESS);
        mKRA.getRequestQueue().updateRequest(request);

        return true;
    }

    //ToDo: return real owner with auth
    private String getOwnerName(IRequest request) {
        return DEFAULT_OWNER;
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

    private String auditSubjectID() {
        if (signedAuditLogger == null) {
            return null;
        }

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String) auditContext.get(SessionContext.USER_ID);
            subjectID = (subjectID != null) ? subjectID.trim() : ILogger.NONROLEUSER;
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    private void auditSymKeyGenRequestProcessed(String subjectID, String status, RequestId requestID, String clientKeyID,
            String keyID, String reason) {
        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SYMKEY_GEN_REQUEST_PROCESSED,
                subjectID,
                status,
                requestID.toString(),
                clientKeyID,
                keyID != null ? keyID : "None",
                reason);
        audit(auditMessage);
    }
}