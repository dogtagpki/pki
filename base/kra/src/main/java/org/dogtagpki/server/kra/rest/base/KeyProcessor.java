//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.base;

import java.math.BigInteger;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.rest.v2.KRAServlet;
import org.dogtagpki.server.rest.v2.PKIServlet;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.HTTPGoneException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.certsrv.key.KeyNotFoundException;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataExportEvent;
import com.netscape.certsrv.logging.event.SecurityDataInfoEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryProcessedEvent;
import com.netscape.certsrv.logging.event.SecurityDataStatusChangeEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.kra.KeyRecoveryAuthority;
/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
public class KeyProcessor {
    public static final String KEY_STATUS_ACTIVE = "active";
    public static final String KEY_STATUS_INACTIVE = "inactive";
    public static final String ATTR_SERIALNO = "serialNumber";

    private static final Logger logger = LoggerFactory.getLogger(KeyProcessor.class);

    private KRAEngine engine;
    private KeyRepository repo;
    private KeyRecoveryAuthority kra;
    private RequestRepository requestRepository;
    private RequestQueue queue;
    private KeyRecoveryAuthority service;
    private Auditor auditor;

    public KeyProcessor(KRAEngine engine) {
        this.engine = engine;
        kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
        repo = engine.getKeyRepository();
        requestRepository = engine.getRequestRepository();
        queue = engine.getRequestQueue();
        service = kra;
        auditor = engine.getAuditor();
    }

    public KeyInfoCollection listKeys(Principal principal, String baseUrl, String clientKeyID, String status, int maxResults, int maxTime, int start,
            int size, String realm, String owner) {
        logger.info("Key: Searching for keys");
        logger.info("Key: - client key ID: {}", clientKeyID);
        logger.info("Key: - status: {}", status);

        String auditInfo = "Key.listKeyInfos; status =" + status;

        if (realm != null) {
            try {
                AuthzSubsystem authz = engine.getAuthzSubsystem();
                authz.checkRealm(realm, getAuthToken(principal), null, "certServer.kra.keys", "list");

            } catch (EAuthzAccessDenied e) {
                throw new UnauthorizedException("Unauthorized: " + e.getMessage(), e);

            } catch (EAuthzUnknownRealm e) {
                throw new BadRequestException("Unknown realm: " + e.getMessage(), e);

            } catch (EBaseException e) {
                logger.error("Unable to access realm: " + e.getMessage(), e);
                throw new PKIException("Unable to access realm: " + e.getMessage(), e);
            }
        }

        // get ldap filter
        String filter = createSearchFilter(status, clientKeyID, realm, owner);
        logger.info("Key: - filter: {}", filter);


        KeyInfoCollection infos = new KeyInfoCollection();
        try {
            Enumeration<KeyRecord> e = repo.searchKeys(filter, maxResults, maxTime);
            if (e == null) {
                return infos;
            }

            logger.info("Key: Results:");

            // store non-null results in a list
            List<KeyInfo> results = new ArrayList<>();
            while (e.hasMoreElements()) {
                KeyRecord rec = e.nextElement();
                if (rec == null) continue;

                KeyInfo info = createKeyDataInfo(rec, baseUrl, false);
                logger.info("Key: - key: {}", info.getKeyId());
                results.add(info);

                auditKeyInfoSuccess(principal, info.getKeyId(), null, auditInfo);
            }
            int total = results.size();
            logger.info("Key: Total: {}", total);
            infos.setTotal(total);

            // return entries in the requested page
            for (int i = start; i < start + size && i < total; i++) {
                infos.addEntry(results.get(i));
            }
        } catch (EBaseException e) {
            throw new PKIException("Unable to list keys: " + e.getMessage(), e);
        }
        return infos;
    }

    public KeyInfo getKeyInfo(Principal principal, String baseUrl, KeyId keyId) {
        String auditInfo = "Key.getKeyInfo";
        logger.debug("Key.getKeyInfo: begins.");

        KeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());

            AuthzSubsystem authz = engine.getAuthzSubsystem();
            authz.checkRealm(rec.getRealm(), getAuthToken(principal), rec.getOwnerName(), "certServer.kra.key", "read");

            KeyInfo info = createKeyDataInfo(rec, baseUrl, true);
            auditKeyInfoSuccess(principal, keyId, null, auditInfo);

            return info;
        } catch (EAuthzAccessDenied e) {
            String message = "Unauthorized access for key record";
            auditKeyInfoError(principal, keyId, null, message, auditInfo);
            throw new UnauthorizedException(message, e);
        } catch (DBRecordNotFoundException e) {
            String message = "key not found";
            auditKeyInfoError(principal, keyId, null, message, auditInfo);
            throw new KeyNotFoundException(keyId, message, e);
        } catch (Exception e) {
            auditKeyInfoError(principal, keyId, null, e.getMessage(), auditInfo);
            throw new PKIException(e.getMessage(), e);
        }
    }

    public KeyInfo getActiveKeyInfo(Principal principal, String baseUrl, String clientKeyID) {
        String auditInfo = "Key.getActiveKeyInfo";
        logger.debug("Key.getActiveKeyInfo: begins.");

        KeyInfoCollection infos = listKeys(
                principal,
                baseUrl,
                clientKeyID,
                KEY_STATUS_ACTIVE,
                KRAServlet.DEFAULT_MAXRESULTS,
                PKIServlet.DEFAULT_MAXTIME,
                0,
                PKIServlet.DEFAULT_SIZE,
                null,
                null
        );

        Collection<KeyInfo> list = infos.getEntries();
        Iterator<KeyInfo> iter = list.iterator();

        while (iter.hasNext()) {
            KeyInfo info = iter.next();
            if (info != null) {
                // return the first one, but first confirm that the requester has access to this key
                try {
                    AuthzSubsystem authz = engine.getAuthzSubsystem();
                    authz.checkRealm(info.getRealm(), getAuthToken(principal), info.getOwnerName(), "certServer.kra.key", "read");
                } catch (EAuthzAccessDenied e) {
                    String message = "Not authorized to read this key";
                    auditKeyInfoError(principal, null, clientKeyID, message, auditInfo);
                    throw new UnauthorizedException("Not authorized to read this key", e);
                } catch (EBaseException e) {
                    logger.error("listRequests: unable to authorize realm: " + e.getMessage(), e);
                    auditKeyInfoError(principal, null, clientKeyID, e.getMessage(), auditInfo);
                    throw new PKIException(e.toString(), e);
                }
                auditKeyInfoSuccess(principal, info.getKeyId(), clientKeyID, auditInfo);
                return info;
            }
        }
        String message = "Key not found";
        auditKeyInfoError(principal, null, clientKeyID, message, auditInfo);
        throw new ResourceNotFoundException(message);
    }

    public void modifyKeyStatus(Principal principal, String baseUrl, KeyId id, String status) {
        String auditInfo = "Key.modifyKeyStatus";
        String messageError =  "Unable to modify key status: ";
        //TODO: what was the original status?  find it and record that in Info as well

        logger.info("Key.modifyKeyStatus: Modifying key {} status to {}", id, status);

        KeyRecord rec = null;
        KeyInfo info = null;
        try {
            rec = repo.readKeyRecord(id.toBigInteger());
            info = createKeyDataInfo(rec, baseUrl,  true); // for getting the old status for auditing purpose

            ModificationSet mods = new ModificationSet();
            mods.add(KeyRecord.ATTR_STATUS, Modification.MOD_REPLACE, status);

            repo.modifyKeyRecord(id.toBigInteger(), mods);

            logger.info("Key status modified");

            auditKeyStatusChange(principal, ILogger.SUCCESS, id,
                    (info!=null)?info.getStatus():null, status, auditInfo);

        } catch (DBRecordNotFoundException e) {

            logger.error(messageError + e.getMessage(), e);

            auditInfo = auditInfo + ":" + e.getMessage();
            auditKeyStatusChange(principal, ILogger.FAILURE, id,
                    (info!=null)?info.getStatus():null, status, auditInfo);
            throw new KeyNotFoundException(id, "key not found to modify", e);

        } catch (Exception e) {

            logger.error(messageError + e.getMessage(), e);

            auditInfo = auditInfo + ":" + e.getMessage();
            auditKeyStatusChange(principal, ILogger.FAILURE, id,
                    (info!=null)?info.getStatus():null, status, auditInfo);
            throw new PKIException(messageError + e.getMessage(), e);
        }
    }

    public KeyData retrieveKey(Principal principal, KeyRecoveryRequest data) {
        if (data == null) {
            auditRetrieveKeyError(principal, null, null, "Key: Missing key recovery request", null);
            throw new BadRequestException("Missing key recovery request");
        }

        try {
            logger.debug("Key: Request:\n{}", data.toJSON());
        } catch (JsonProcessingException e) {
            auditRetrieveKeyError(principal, null, null, "Key: Problem processing key data", null);
            throw new PKIException(e.getMessage(), e);
        }

        String auditInfo = "Key.retrieveKey";

        String realm = null;
        boolean synchronous = false;
        boolean ephemeral = false;

        // get or create request
        RequestId requestId = data.getRequestId();
        KeyId keyId = null;
        Request request = null;

        if (requestId != null) {

            logger.debug("Key: Searching for asynchronous request {}", requestId);
            // We assume that the request is valid and has been approved

            auditInfo += ";requestID=" + requestId;

            try {
                request = requestRepository.readRequest(requestId);
            } catch (EBaseException e) {
                auditRetrieveKeyError(principal, requestId, keyId, e.getMessage(), auditInfo);
                throw new PKIException(e.getMessage(), e);
            }

            if (request == null) {
                auditRetrieveKeyError(principal, requestId, keyId, "Request not found: " + requestId, auditInfo);
                throw new BadRequestException("Request not found: " + requestId);
            }

            keyId = new KeyId(request.getExtDataInString(ATTR_SERIALNO));
            logger.debug("Key: Request found for key {}", keyId);

            auditInfo += ";keyID=" + keyId;

            data.setKeyId(keyId);

        } else {

            keyId = data.getKeyId();
            logger.info("Key: Retrieving key {}", keyId);

            if (keyId == null) {
                auditRetrieveKeyError(principal, requestId, keyId, "Missing recovery request ID and key ID", auditInfo);
                throw new BadRequestException("Missing recovery request ID and key ID");
            }

            auditInfo += ";keyID=" + keyId;

            // TODO(alee): get the realm from the key record
            logger.info("Key: realm: {}", realm);

            synchronous = kra.isRetrievalSynchronous(realm);
            logger.info("Key: synchronous: {}", synchronous);

            ephemeral = kra.isEphemeral(realm);
            logger.info("Key: ephemeral: {}", ephemeral);

            // Only synchronous requests can be ephemeral
            if (!synchronous) ephemeral = false;

            auditInfo += ";synchronous=" + synchronous;
            auditInfo += ";ephemeral=" + ephemeral;

            logger.info("Key: Creating recovery request");

            KeyRequestDAO reqDAO = new KeyRequestDAO();
            try {
                request = reqDAO.createRecoveryRequest(
                        data, null, principal.getName(), getAuthToken(principal), ephemeral);
            } catch (EBaseException e) {
                auditRetrieveKeyError(principal, requestId, keyId, "Unable to create recovery request: " + e.getMessage(), auditInfo);
                throw new PKIException("Unable to create recovery request: " + e.getMessage(), e);
            }

            requestId = request.getRequestId();
            logger.info("Key: Created request {}", requestId);

            auditInfo += ";requestID=" + requestId;

            if (!synchronous) {
                logger.info("Key: Storing request in database");

                try {
                    requestRepository.updateRequest(request);
                } catch (EBaseException e) {
                    logger.error("KeyService: " + e.getMessage(), e);
                    auditRecoveryRequest(principal, ILogger.FAILURE, requestId, keyId);
                    throw new PKIException(e.getMessage(), e);
                }
                KeyData keyData = new KeyData();
                keyData.setRequestID(requestId);

                try {
                    logger.debug("Key: Response:\n {}", keyData.toJSON());
                } catch (JsonProcessingException e) {
                    auditRecoveryRequest(principal, ILogger.FAILURE, requestId, keyId);
                    throw new PKIException(e.getMessage(), e);
                }

                auditRecoveryRequest(principal, ILogger.SUCCESS, requestId, keyId);

                logger.info("Key: Returning created recovery request");
                return keyData;
            }
            auditRecoveryRequest(principal, ILogger.SUCCESS, requestId, keyId);
        }

        data.setRequestId(requestId);

        String type = request.getRequestType();
        logger.debug("Key: request type: {}", type);
        auditInfo += ";request type:" + type;

        // process request
        KeyData keyData = null;
        try {
            switch(type) {
                case Request.KEYRECOVERY_REQUEST:

                    logger.info("Key: Processing key recovery request");
                    keyData = recoverKey(data);
                    auditInfo = "Key.recoverKey";
                    break;

                case Request.SECURITY_DATA_RECOVERY_REQUEST:

                    logger.info("KeyService: Processing security data recovery request");
                    if (synchronous)  request.setRequestStatus(RequestStatus.APPROVED);
                    validateRequest(principal, data, request);
                    keyData = getKey(keyId, request, data, synchronous, ephemeral);

                    auditInfo += "Key.getKey: keyID=" + keyId.toString();
                    auditInfo += ";requestID=" + requestId.toString();
                    auditInfo += ";synchronous=" + Boolean.toString(synchronous);
                    auditInfo += ";ephemeral=" + Boolean.toString(ephemeral);
                    break;

                default:
                    throw new BadRequestException("Invalid request type: " + type);
            }

        } catch (Exception e) {
            auditRecoveryRequestProcessed(principal, ILogger.FAILURE, requestId, keyId, e.getMessage(), auditInfo, null);
            throw new PKIException(e.getMessage(), e);
        }

        if (keyData == null) {
            auditRecoveryRequestProcessed(principal, ILogger.FAILURE, requestId, keyId, "No key record", auditInfo, null);
            throw new HTTPGoneException("No key record.");
        }

        String approvers = request.getExtDataInString(Request.ATTR_APPROVE_AGENTS);
        auditRecoveryRequestProcessed(principal, ILogger.SUCCESS, requestId, keyId, null, auditInfo, approvers);

        try {
            logger.debug("KeyService: Response:\n {}", keyData.toJSON());
        } catch (JsonProcessingException e) {
            auditRecoveryRequestProcessed(principal, ILogger.FAILURE, requestId, keyId, "Key record data error", auditInfo, null);
            throw new PKIException(e.getMessage(), e);
        }

        auditRetrieveKey(principal, ILogger.SUCCESS, requestId, keyId, auditInfo);
        return keyData;
    }

    private AuthToken getAuthToken(Principal principal) {
        if (principal instanceof PKIPrincipal pkiprincipal) {
            AuthToken authToken = pkiprincipal.getAuthToken();
            return authToken;
        }
        throw new PKIException("Unable to access realm: principal not instance of PKIPrincipal");
    }

    private String createSearchFilter(String status, String clientKeyID, String realm, String ownerName) {
        String filter = "";
        int matches = 0;

        if ((status == null) && (clientKeyID == null) && (ownerName == null)) {
            filter = "(serialno=*)";
            matches ++;
        }

        if (ownerName != null) {
            filter = "(keyOwnerName=" + LDAPUtil.escapeFilter(ownerName) + ")";
            matches ++;
        }

        if (status != null) {
            filter += "(status=" + LDAPUtil.escapeFilter(status) + ")";
            matches ++;
        }

        if (clientKeyID != null) {
            filter += "(clientID=" + LDAPUtil.escapeFilter(clientKeyID) + ")";
            matches ++;
        }

        if (realm != null) {
            filter += "(realm=" + LDAPUtil.escapeFilter(realm) + ")";
            matches ++;
        } else {
            filter += "(!(realm=*))";
            matches ++;
        }

        if (matches > 1) {
            filter = "(&" + filter + ")";
        }
        return filter;
    }

    private KeyInfo createKeyDataInfo(KeyRecord rec, String baseURL, boolean getPublicKey) throws EBaseException {
        String method = "Key.createKeyDataInfo: ";
        logger.debug("{} begins.", method);

        KeyInfo ret = new KeyInfo();
        ret.setClientKeyID(rec.getClientId());
        ret.setStatus(rec.getKeyStatus());
        ret.setAlgorithm(rec.getAlgorithm());
        ret.setSize(rec.getKeySize());
        ret.setOwnerName(rec.getOwnerName());
        if (rec.getPublicKeyData() != null && getPublicKey) {
            ret.setPublicKey(rec.getPublicKeyData());
        }
        String realm = rec.getRealm();
        if (realm != null) {
            ret.setRealm(realm);
        }

        BigInteger serial = rec.getSerialNumber();
        KeyId keyID = new KeyId(serial);
        ret.setKeyId(keyID);


        StringBuilder keyPath = new StringBuilder(baseURL);
        if (!baseURL.endsWith("/"))
            keyPath.append("/");
        keyPath.append(keyID.toHexString());
        ret.setKeyURL(keyPath.toString());
        return ret;
    }

    private KeyData recoverKey(KeyRecoveryRequest data) throws Exception {

        String method = "Key.recoverKey:";
        logger.debug("{} begins.", method);

        RequestId reqId = data.getRequestId();

        // confirm request exists
        Request request = requestRepository.readRequest(reqId);

        if (request == null) {
            throw new HTTPGoneException("Request not found: " + reqId);
        }

        String type = request.getRequestType();
        RequestStatus status = request.getRequestStatus();

        if (!Request.KEYRECOVERY_REQUEST.equals(type) ||
            !status.equals(RequestStatus.APPROVED)) {
            throw new UnauthorizedException("Request not approved");
        }

        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.setTransientData(data, request);
        } catch(EBaseException e) {
            throw new PKIException("Unable to set transient data: " + e.getMessage(), e);
        }

        String passphrase = data.getPassphrase();
        byte[] pkcs12 = service.doKeyRecovery(request, passphrase);

        if (pkcs12 == null) {
            throw new HTTPGoneException("Unable to generate PKCS #12 file");
        }

        String pkcs12base64encoded = Utils.base64encode(pkcs12, false);

        KeyData keyData = new KeyData();
        keyData.setP12Data(pkcs12base64encoded);

        try {
            queue.processRequest(request);
            logger.debug("{} queue.processRequest returned", method);
            queue.markAsServiced(request);
        } catch (EBaseException e) {
            // intentionally not propagating
            logger.debug("{} queue.processRequest failed bug ignored: {}", method,  e.toString());
        }

        return keyData;
    }
    private void validateRequest(Principal principal, KeyRecoveryRequest data, Request request) {
        logger.debug("Key.validateRequest: begins.");

        // confirm that at least one wrapping method exists
        // There must be at least the wrapped session key method.
        if ((data.getTransWrappedSessionKey() == null)) {
            throw new BadRequestException("No wrapping method found.");
        }

        // confirm that the keyIDs match
        String keyID = request.getExtDataInString(ATTR_SERIALNO);
        if (!data.getKeyId().toString().contentEquals(keyID)) {
            throw new UnauthorizedException("Key IDs do not match");
        }

        //confirm that retriever is originator of request, else throw 401
        String retriever = principal.getName();
        String originator = request.getExtDataInString(Request.ATTR_REQUEST_OWNER);
        if (! originator.equals(retriever)) {
            throw new UnauthorizedException("Data can only be retrieved by the originators of the request");
        }

        // confirm request is in approved state
        RequestStatus status = request.getRequestStatus();
        if (!status.equals(RequestStatus.APPROVED)) {
            throw new UnauthorizedException("Recovery request not approved.");
        }
    }

    private KeyData getKey(KeyId keyId, Request request, KeyRecoveryRequest data,
            boolean synchronous, boolean ephemeral) throws EBaseException {
        String method = "Key.getKey:";
        KeyData keyData;
        KeyRequestDAO dao = new KeyRequestDAO();
        logger.debug("{} begins.", method);

        if (data == null) {
            logger.warn("{} KeyRecoveryRequest is null", method);
            return null;
        }

        if (request == null) {
            logger.warn("{} request null", method);
            return null;
        }

        // get wrapped key
        KeyRecord rec = repo.readKeyRecord(keyId.toBigInteger());
        if (rec == null) {
            logger.warn("{} key record null", method);
            return null;
        }

        // get data from IRequest
        Hashtable<String, Object> requestParams = dao.getTransientData(request);

        String sessWrappedKeyData = (String) requestParams.get(Request.SECURITY_DATA_SESS_WRAPPED_DATA);
        String passWrappedKeyData = (String) requestParams.get(Request.SECURITY_DATA_PASS_WRAPPED_DATA);
        String nonceData = (String) requestParams.get(Request.SECURITY_DATA_IV_STRING_OUT);

        if (sessWrappedKeyData != null || passWrappedKeyData != null) {
            //The recovery process has already placed a valid recovery
            //package, either session key wrapped or pass wrapped, into the request.
            //Request already has been processed.
            keyData = new KeyData();
        } else {
            // The request has not yet been processed, let's see if the RecoveryRequestData contains
            // the info now needed to process the recovery request.

            nonceData = data.getNonceData();
            dao.setTransientData(data, request);

            try {
                if (!synchronous) {
                    // Has to be in this state or it won't go anywhere.
                    request.setRequestStatus(RequestStatus.BEGIN);
                    queue.processRequest(request);
                } else {
                    kra.processSynchronousRequest(request);
                }
            } catch (EBaseException e) {
                kra.destroyVolatileRequest(request.getRequestId());
                throw new PKIException(e.getMessage(), e);
            }

            // get the results of the operations
            keyData = new KeyData();
            sessWrappedKeyData = (String) requestParams.get(Request.SECURITY_DATA_SESS_WRAPPED_DATA);
            passWrappedKeyData = (String) requestParams.get(Request.SECURITY_DATA_PASS_WRAPPED_DATA);
            nonceData = (String) requestParams.get(Request.SECURITY_DATA_IV_STRING_OUT);
        }

        if (sessWrappedKeyData != null) {
            keyData.setWrappedPrivateData(sessWrappedKeyData);
        }
        if (passWrappedKeyData != null) {
            keyData.setWrappedPrivateData(passWrappedKeyData);
        }
        if (nonceData != null) {
            keyData.setNonceData(nonceData);
        }

        keyData.setType((String) requestParams.get(Request.SECURITY_DATA_TYPE));

        String payloadWrapped = (String) requestParams.get(Request.SECURITY_DATA_PL_WRAPPED);
        // either wrapAlgorithm or encryptAlgorithm will be set.  This will tell the
        // client which mechanism was used to encrypt the secret
        if (payloadWrapped.equalsIgnoreCase("true")) {
            keyData.setWrapAlgorithm(
                    (String) requestParams.get(Request.SECURITY_DATA_PL_WRAPPING_NAME));
        } else {
            keyData.setEncryptAlgorithmOID(
                    (String) requestParams.get(Request.SECURITY_DATA_PL_ENCRYPTION_OID));
        }

        String algorithm = rec.getAlgorithm();
        if (algorithm != null) {
            keyData.setAlgorithm(algorithm);
        }

        Integer keySize = rec.getKeySize();
        if (keySize != null) {
            keyData.setSize(keySize);
        }

        byte[] pubKeyBytes =  rec.getPublicKeyData();
        if (pubKeyBytes != null) {
            keyData.setPublicKey(Utils.base64encode(pubKeyBytes, true));
        }

        kra.destroyVolatileRequest(request.getRequestId());

        if (!synchronous) {
            queue.markAsServiced(request);
        } else {
            request.setRequestStatus(RequestStatus.COMPLETE);
            if (! ephemeral) {
                // stores the request in LDAP
                requestRepository.updateRequest(request);
            }
        }

        return keyData;
    }

    private void auditKeyInfo(Principal principal, KeyId keyId, String clientKeyId, String status, String reason, String auditInfo) {
        auditor.log(new SecurityDataInfoEvent(
                principal.getName(),
                status,
                keyId,
                clientKeyId,
                (reason != null) ? auditInfo + ";" + reason : auditInfo,
                null
        ));
    }

    private void auditKeyInfoSuccess(Principal principal, KeyId keyId, String clientKeyId, String info) {
        auditKeyInfo(principal, keyId, clientKeyId, ILogger.SUCCESS, null, info);
    }

    private void auditKeyInfoError(Principal principal, KeyId keyId, String clientKeyId, String message, String info) {
        logger.warn(message);
        auditKeyInfo(principal, keyId, clientKeyId, ILogger.FAILURE, message, info);
    }

    private void auditKeyStatusChange(Principal principal, String status, KeyId keyID, String oldKeyStatus,
            String newKeyStatus, String info) {
        auditor.log(new SecurityDataStatusChangeEvent(
                principal.getName(),
                status,
                keyID,
                oldKeyStatus,
                newKeyStatus,
                info));
    }

    private void auditRecoveryRequest(Principal principal, String status, RequestId requestId, KeyId keyId) {
        auditor.log(new SecurityDataRecoveryEvent(
                principal.getName(),
                status,
                requestId,
                keyId,
                null
        ));
    }

    private void auditRecoveryRequestProcessed(Principal principal, String status, RequestId requestId, KeyId keyId, String reason, String info, String approvers) {
        auditor.log(new SecurityDataRecoveryProcessedEvent(
                principal.getName(),
                status,
                requestId,
                keyId,
                (reason != null) ? info + ";" + reason : info,
                approvers
        ));
    }

    private void auditRetrieveKey(Principal principal, String status, RequestId requestId, KeyId keyId, String reason, String auditInfo) {
        auditor.log(new SecurityDataExportEvent(
                principal.getName(),
                status,
                requestId,
                keyId,
                (reason != null) ? auditInfo + ";" + reason : auditInfo,
                null
        ));
    }

    private void auditRetrieveKey(Principal principal, String status, RequestId requestId, KeyId keyId, String auditInfo) {
        auditRetrieveKey(principal, status, requestId, keyId, null, auditInfo);
    }

    private void auditRetrieveKeyError(Principal principal, RequestId requestId, KeyId keyId, String reason, String auditInfo) {
        logger.warn(reason);
        auditRetrieveKey(principal, ILogger.FAILURE, requestId, keyId, reason, auditInfo);
    }
}
