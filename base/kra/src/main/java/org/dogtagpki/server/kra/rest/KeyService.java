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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.kra.rest;


import java.math.BigInteger;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import javax.ws.rs.Path;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.HTTPGoneException;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.certsrv.key.KeyNotFoundException;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyResource;
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataExportEvent;
import com.netscape.certsrv.logging.event.SecurityDataInfoEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryProcessedEvent;
import com.netscape.certsrv.logging.event.SecurityDataStatusChangeEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.request.ARequestQueue;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * @author alee
 *
 */
public class KeyService extends SubsystemService implements KeyResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyService.class);

    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;
    public static final String ATTR_SERIALNO = "serialNumber";

    private KeyRepository repo;
    private KeyRecoveryAuthority kra;
    private RequestRepository requestRepository;
    private ARequestQueue queue;
    private IKeyService service;

    //parameters for auditing
    private RequestId requestId;
    private KeyId keyId;
    private String auditInfo;
    private String approvers;

    public KeyService() {
        KRAEngine engine = KRAEngine.getInstance();
        kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
        repo = kra.getKeyRepository();
        requestRepository = engine.getRequestRepository();
        queue = engine.getRequestQueue();
        service = kra;
    }

    /**
     * Used to retrieve a key
     *
     * There are two use cases here:
     * 1. asynchronous requests
     * 2. synchronous requests
     * @param data
     * @return
     */
    @Override
    public Response retrieveKey(KeyRecoveryRequest data) {

        logger.info("KeyService: Processing key recovery request");

        try {
            Response response = retrieveKeyImpl(data);
            return response;

        } catch(RuntimeException e) {
            logger.error("Unable to recover key: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("Unable to recover key: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Response retrieveKeyImpl(KeyRecoveryRequest data) throws Exception {

        if (data == null) {
            auditRetrieveKeyError("KeyService: Missing key recovery request");
            throw new BadRequestException("Missing key recovery request");
        }

        logger.info("KeyService: Request:\n" + data.toJSON());

        auditInfo = "KeyService.retrieveKey";

        String realm = null;
        boolean synchronous = false;
        boolean ephemeral = false;

        // get or create request
        requestId = data.getRequestId();
        IRequest request = null;

        if (requestId != null) {

            logger.debug("KeyService: Searching for asynchronous request " + requestId);
            // We assume that the request is valid and has been approved

            auditInfo += ";requestID=" + requestId;

            try {
                request = requestRepository.readRequest(requestId);
            } catch (EBaseException e) {
                auditRetrieveKeyError(e.getMessage());
                throw new PKIException(e.getMessage(), e);
            }

            if (request == null) {
                auditRetrieveKeyError("Request not found: " + requestId);
                throw new BadRequestException("Request not found: " + requestId);
            }

            keyId = new KeyId(request.getExtDataInString(ATTR_SERIALNO));
            logger.debug("KeyService: Request found for key " + keyId);

            auditInfo += ";keyID=" + keyId;

            data.setKeyId(keyId);

        } else {

            keyId = data.getKeyId();
            logger.info("KeyService: Retrieving key " + keyId);

            if (keyId == null) {
                auditRetrieveKeyError("Missing recovery request ID and key ID");
                throw new BadRequestException("Missing recovery request ID and key ID");
            }

            auditInfo += ";keyID=" + keyId;

            // TODO(alee): get the realm from the key record
            logger.info("KeyService: realm: " + realm);

            synchronous = kra.isRetrievalSynchronous(realm);
            logger.info("KeyService: synchronous: " + synchronous);

            ephemeral = kra.isEphemeral(realm);
            logger.info("KeyService: ephemeral: " + ephemeral);

            // Only synchronous requests can be ephemeral
            if (!synchronous) ephemeral = false;

            auditInfo += ";synchronous=" + synchronous;
            auditInfo += ";ephemeral=" + ephemeral;

            logger.info("KeyService: Creating recovery request");

            KeyRequestDAO reqDAO = new KeyRequestDAO();
            try {
                request = reqDAO.createRecoveryRequest(
                        data, uriInfo, getRequestor(), getAuthToken(), ephemeral);
            } catch (EBaseException e) {
                auditRetrieveKeyError("Unable to create recovery request: " + e.getMessage());
                throw new PKIException("Unable to create recovery request: " + e.getMessage(), e);
            }

            requestId = request.getRequestId();
            logger.info("KeyService: Created request " + requestId);

            auditInfo += ";requestID=" + requestId;

            if (!synchronous) {

                logger.info("KeyService: Storing request in database");

                try {
                    queue.updateRequest(request);
                } catch (EBaseException e) {
                    logger.error("KeyService: " + e.getMessage(), e);
                    auditRecoveryRequest(ILogger.FAILURE);
                    throw new PKIException(e.getMessage(), e);
                }

                auditRecoveryRequest(ILogger.SUCCESS);

                logger.info("KeyService: Returning created recovery request");

                KeyData keyData = new KeyData();
                keyData.setRequestID(requestId);

                logger.info("KeyService: Response:\n" + keyData.toJSON());

                return createOKResponse(keyData);
            }

            auditRecoveryRequest(ILogger.SUCCESS);
        }

        data.setRequestId(requestId);

        String type = request.getRequestType();
        logger.debug("KeyService: request type: " + type);
        auditInfo += ";request type:" + type;

        // process request
        KeyData keyData = null;
        try {
            switch(type) {
                case IRequest.KEYRECOVERY_REQUEST:

                    logger.info("KeyService: Processing key recovery request");
                    keyData = recoverKey(data);
                    break;

                case IRequest.SECURITY_DATA_RECOVERY_REQUEST:

                    logger.info("KeyService: Processing security data recovery request");
                    if (synchronous)  request.setRequestStatus(RequestStatus.APPROVED);
                    validateRequest(data, request);
                    keyData = getKey(keyId, request, data, synchronous, ephemeral);
                    break;

                default:
                    throw new BadRequestException("Invalid request type: " + type);
            }

        } catch (Exception e) {
            auditRecoveryRequestProcessed(ILogger.FAILURE, e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }

        if (keyData == null) {
            auditRecoveryRequestProcessed(ILogger.FAILURE, "No key record");
            throw new HTTPGoneException("No key record.");
        }

        approvers = request.getExtDataInString(IRequest.ATTR_APPROVE_AGENTS);
        auditRecoveryRequestProcessed(ILogger.SUCCESS, null);

        logger.info("KeyService: Response:\n" + keyData.toJSON());

        auditRetrieveKey(ILogger.SUCCESS);
        return createOKResponse(keyData);
    }

    // retrieval - used to test integration with a browser
    @Override
    public Response retrieveKey(MultivaluedMap<String, String> form) {
        logger.debug("KeyService.retrieveKey with form: begins.");
        KeyRecoveryRequest data = new KeyRecoveryRequest(form);
        return retrieveKey(data);
    }

    public KeyData getKey(KeyId keyId, IRequest request, KeyRecoveryRequest data,
            boolean synchronous, boolean ephemeral) throws EBaseException {
        String method = "KeyService.getKey:";
        auditInfo = method;
        KeyData keyData;
        KeyRequestDAO dao = new KeyRequestDAO();
        logger.debug(method + "begins.");

        if (data == null) {
            logger.warn(method + "KeyRecoveryRequest is null");
            return null;
        }

        if (request == null) {
            logger.warn(method + "request null");
            return null;
        }

        // get wrapped key
        IKeyRecord rec = repo.readKeyRecord(keyId.toBigInteger());
        if (rec == null) {
            logger.warn(method + "key record null");
            return null;
        }

        auditInfo += ";keyID=" + keyId.toString();
        auditInfo += ";requestID=" + requestId.toString();
        auditInfo += ";synchronous=" + Boolean.toString(synchronous);
        auditInfo += ";ephemeral=" + Boolean.toString(ephemeral);

        // get data from IRequest
        Hashtable<String, Object> requestParams = dao.getTransientData(request);

        String sessWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_SESS_WRAPPED_DATA);
        String passWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_PASS_WRAPPED_DATA);
        String nonceData = (String) requestParams.get(IRequest.SECURITY_DATA_IV_STRING_OUT);

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
            sessWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_SESS_WRAPPED_DATA);
            passWrappedKeyData = (String) requestParams.get(IRequest.SECURITY_DATA_PASS_WRAPPED_DATA);
            nonceData = (String) requestParams.get(IRequest.SECURITY_DATA_IV_STRING_OUT);
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

        keyData.setType((String) requestParams.get(IRequest.SECURITY_DATA_TYPE));

        String payloadWrapped = (String) requestParams.get(IRequest.SECURITY_DATA_PL_WRAPPED);
        // either wrapAlgorithm or encryptAlgorithm will be set.  This will tell the
        // client which mechanism was used to encrypt the secret
        if (payloadWrapped.equalsIgnoreCase("true")) {
            keyData.setWrapAlgorithm(
                    (String) requestParams.get(IRequest.SECURITY_DATA_PL_WRAPPING_NAME));
        } else {
            keyData.setEncryptAlgorithmOID(
                    (String) requestParams.get(IRequest.SECURITY_DATA_PL_ENCRYPTION_OID));
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
                queue.updateRequest(request);
            }
        }

        return keyData;
    }

    private void validateRequest(KeyRecoveryRequest data, IRequest request) {
        String method = "KeyService.validateRequest: ";
        logger.debug(method + "begins.");

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
        String retriever = servletRequest.getUserPrincipal().getName();
        String originator = request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER);
        if (! originator.equals(retriever)) {
            throw new UnauthorizedException("Data can only be retrieved by the originators of the request");
        }

        // confirm request is in approved state
        RequestStatus status = request.getRequestStatus();
        if (!status.equals(RequestStatus.APPROVED)) {
            throw new UnauthorizedException("Recovery request not approved.");
        }
    }

    /**
     * Used to generate list of key infos based on the search parameters
     */
    @Override
    public Response listKeys(String clientKeyID, String status, Integer maxResults, Integer maxTime,
            Integer start, Integer size, String realm) {

        KeyInfoCollection keys = listKeyInfos(clientKeyID, status, maxResults, maxTime, start, size, realm);

        try {
            return createOKResponse(keys);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public KeyInfoCollection listKeyInfos(String clientKeyID, String status, Integer maxResults, Integer maxTime,
            Integer start, Integer size, String realm) {

        logger.info("KeyService: Searching for keys");
        logger.info("KeyService: - client key ID: " + clientKeyID);
        logger.info("KeyService: - status: " + status);

        auditInfo = "KeyService.listKeyInfos; status =" + status;

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        if (realm != null) {
            try {
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.keys", "list");

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
        String filter = createSearchFilter(status, clientKeyID, realm);
        logger.info("KeyService: - filter: " + filter);

        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyInfoCollection infos = new KeyInfoCollection();
        try {
            Enumeration<IKeyRecord> e = repo.searchKeys(filter, maxResults, maxTime);
            if (e == null) {
                return infos;
            }

            logger.info("KeyService: Results:");

            // store non-null results in a list
            List<KeyInfo> results = new ArrayList<KeyInfo>();
            while (e.hasMoreElements()) {
                IKeyRecord rec = e.nextElement();
                if (rec == null) continue;

                KeyInfo info = createKeyDataInfo(rec, false);
                logger.info("KeyService: - key " + info.getKeyId());
                results.add(info);

                auditKeyInfoSuccess(info.getKeyId(), null);
            }

            int total = results.size();
            logger.info("KeyService: Total: " + total);
            infos.setTotal(total);

            // return entries in the requested page
            for (int i = start; i < start + size && i < total; i++) {
                infos.addEntry(results.get(i));
            }

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                infos.addLink(new Link("prev", uri));
            }

            if (start + size < total) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                infos.addLink(new Link("next", uri));
            }

        } catch (EBaseException e) {
            throw new PKIException("Unable to list keys: " + e.getMessage(), e);
        }

        return infos;
    }

    @Override
    public Response getActiveKeyInfo(String clientKeyID) {
        try {
            return getActiveKeyInfoImpl(clientKeyID);
        } catch (RuntimeException e) {
            auditKeyInfoError(null, clientKeyID, e.getMessage());
            throw e;
        } catch (Exception e) {
            auditKeyInfoError(null, clientKeyID, e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Response getActiveKeyInfoImpl(String clientKeyID) {
        String method = "KeyService.getActiveKeyInfo: ";
        auditInfo = "KeyService.getActiveKeyInfo";
        logger.debug(method + "begins.");

        KeyInfoCollection infos = listKeyInfos(
                clientKeyID,
                "active",
                null,
                null,
                null,
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
                    authz.checkRealm(info.getRealm(), getAuthToken(), info.getOwnerName(), "certServer.kra.key", "read");
                } catch (EAuthzAccessDenied e) {
                    throw new UnauthorizedException("Not authorized to read this key", e);
                } catch (EBaseException e) {
                    logger.error("listRequests: unable to authorize realm: " + e.getMessage(), e);
                    throw new PKIException(e.toString(), e);
                }

                auditKeyInfoSuccess(info.getKeyId(), clientKeyID);

                return createOKResponse(info);
            }
        }
        throw new ResourceNotFoundException("Key not found");
    }

    public KeyInfo createKeyDataInfo(IKeyRecord rec, boolean getPublicKey) throws EBaseException {
        String method = "KeyService.createKeyDataInfo: ";
        logger.debug(method + "begins.");

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

        Path keyPath = KeyResource.class.getAnnotation(Path.class);
        BigInteger serial = rec.getSerialNumber();

        UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
        keyBuilder.path(keyPath.value() + "/" + serial);
        ret.setKeyURL(keyBuilder.build().toString());

        return ret;
    }

    private String createSearchFilter(String status, String clientKeyID, String realm) {
        String filter = "";
        int matches = 0;

        if ((status == null) && (clientKeyID == null)) {
            filter = "(serialno=*)";
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

    public void auditRetrieveKey(String status, String reason) {
        signedAuditLogger.log(new SecurityDataExportEvent(
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId,
                keyId,
                (reason != null) ? auditInfo + ";" + reason : auditInfo,
                null
        ));
    }

    public void auditRetrieveKey(String status) {
        auditRetrieveKey(status, null);
    }

    public void auditRetrieveKeyError(String message) {
        logger.warn(message);
        auditRetrieveKey(ILogger.FAILURE, message);
    }

    public void auditKeyInfo(KeyId keyId, String clientKeyId, String status, String reason) {
        signedAuditLogger.log(new SecurityDataInfoEvent(
                servletRequest.getUserPrincipal().getName(),
                status,
                keyId,
                clientKeyId,
                (reason != null) ? auditInfo + ";" + reason : auditInfo,
                null
        ));
    }

    public void auditKeyInfoSuccess(KeyId keyid, String clientKeyId) {
        auditKeyInfo(keyId, clientKeyId, ILogger.SUCCESS, null);
    }

    public void auditKeyInfoError(KeyId keyId, String clientKeyId, String message) {
        logger.warn(message);
        auditKeyInfo(keyId, clientKeyId, ILogger.FAILURE, message);
    }

    public void auditKeyStatusChange(String status, KeyId keyID, String oldKeyStatus,
            String newKeyStatus, String info) {
        signedAuditLogger.log(new SecurityDataStatusChangeEvent(
                servletRequest.getUserPrincipal().getName(),
                status,
                keyID,
                oldKeyStatus,
                newKeyStatus,
                info));
    }

    public void auditRecoveryRequest(String status) {
        signedAuditLogger.log(new SecurityDataRecoveryEvent(
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId,
                keyId,
                null
        ));
    }

    public void auditRecoveryRequestProcessed(String status, String reason) {
        signedAuditLogger.log(new SecurityDataRecoveryProcessedEvent(
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId,
                keyId,
                (reason != null) ? auditInfo + ";" + reason : auditInfo,
                approvers
        ));
    }

    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    private KeyData recoverKey(KeyRecoveryRequest data) throws Exception {

        String method = "KeyService.recoverKey: ";
        auditInfo = "KeyService.recoverKey";
        logger.debug(method + "begins.");

        RequestId reqId = data.getRequestId();

        // confirm request exists
        IRequest request = requestRepository.readRequest(reqId);

        if (request == null) {
            throw new HTTPGoneException("Request not found: " + reqId);
        }

        String type = request.getRequestType();
        RequestStatus status = request.getRequestStatus();

        if (!IRequest.KEYRECOVERY_REQUEST.equals(type) ||
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
        byte[] pkcs12 = service.doKeyRecovery(reqId.toString(), passphrase);

        if (pkcs12 == null) {
            throw new HTTPGoneException("Unable to generate PKCS #12 file");
        }

        String pkcs12base64encoded = Utils.base64encode(pkcs12, false);

        KeyData keyData = new KeyData();
        keyData.setP12Data(pkcs12base64encoded);

        try {
            queue.processRequest(request);
            logger.debug(method + "queue.processRequest returned");
            queue.markAsServiced(request);
        } catch (EBaseException e) {
            // intentionally not propagating
            logger.debug(method + "queue.processRequest failed bug ignored: " + e.toString());
        }

        return keyData;
    }

    @Override
    public Response getKeyInfo(KeyId keyId) {
        try {
            return getKeyInfoImpl(keyId);
        } catch (RuntimeException e) {
            auditKeyInfoError(keyId, null, e.getMessage());
            throw e;
        } catch (Exception e) {
            auditKeyInfoError(keyId, null, e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Response getKeyInfoImpl(KeyId keyId) {
        String method = "KeyService.getKeyInfo: ";
        auditInfo = "KeyService.getKeyInfo";
        logger.debug(method + "begins.");

        IKeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
            authz.checkRealm(rec.getRealm(), getAuthToken(), rec.getOwnerName(), "certServer.kra.key", "read");
            KeyInfo info = createKeyDataInfo(rec, true);
            auditKeyInfoSuccess(keyId, null);

            return createOKResponse(info);
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Unauthorized access for key record", e);
        } catch (EDBRecordNotFoundException e) {
            throw new KeyNotFoundException(keyId, "key not found", e);
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    private IAuthToken getAuthToken() {
        Principal principal = servletRequest.getUserPrincipal();
        PKIPrincipal pkiprincipal = (PKIPrincipal) principal;
        IAuthToken authToken = pkiprincipal.getAuthToken();
        return authToken;
    }

    @Override
    public Response modifyKeyStatus(KeyId keyId, String status) {

        String method = "KeyService.modifyKeyStatus: ";
        //TODO: what was the original status?  find it and record that in Info as well
        auditInfo = "KeyService.modifyKeyStatus";

        logger.info("Modifying key " + keyId + " status to " + status);

        IKeyRecord rec = null;
        KeyInfo info = null;
        try {

            rec = repo.readKeyRecord(keyId.toBigInteger());
            info = createKeyDataInfo(rec, true); // for getting the old status for auditing purpose

            ModificationSet mods = new ModificationSet();
            mods.add(IKeyRecord.ATTR_STATUS, Modification.MOD_REPLACE, status);

            repo.modifyKeyRecord(keyId.toBigInteger(), mods);

            logger.info("Key status modified");

            auditKeyStatusChange(ILogger.SUCCESS, keyId,
                    (info!=null)?info.getStatus():null, status, auditInfo);

            return createNoContentResponse();

        } catch (EDBRecordNotFoundException e) {

            logger.error("Unable to modify key status: " + e.getMessage(), e);

            auditInfo = auditInfo + ":" + e.getMessage();
            auditKeyStatusChange(ILogger.FAILURE, keyId,
                    (info!=null)?info.getStatus():null, status, auditInfo);
            throw new KeyNotFoundException(keyId, "key not found to modify", e);

        } catch (Exception e) {

            logger.error("Unable to modify key status: " + e.getMessage(), e);

            auditInfo = auditInfo + ":" + e.getMessage();
            auditKeyStatusChange(ILogger.FAILURE, keyId,
                    (info!=null)?info.getStatus():null, status, auditInfo);

            throw new PKIException("Unable to modify key status: " + e.getMessage(), e);
        }
    }

    private String getRequestor() {
        return servletRequest.getUserPrincipal().getName();
    }
}
