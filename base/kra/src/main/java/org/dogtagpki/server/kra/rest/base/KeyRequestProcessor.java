//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.base;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyNotFoundException;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AsymKeyGenerationEvent;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryStateChangeEvent;
import com.netscape.certsrv.logging.event.SymKeyGenerationEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
public class KeyRequestProcessor {
    private static final Logger logger = LoggerFactory.getLogger(KeyRequestProcessor.class);

    private KRAEngine engine;
    private KRAEngineConfig cs;
    private KeyRepository repo;
    private RequestRepository requestRepository;
    private RequestQueue queue;
    private AuthzSubsystem authz;
    private Auditor auditor;
    private KeyRecoveryAuthority kra;

    private static final Map<String, SymmetricKey.Type> SYMKEY_TYPES;
    static {
        SYMKEY_TYPES = new HashMap<>();
        SYMKEY_TYPES.put(KeyRequestResource.DES_ALGORITHM, SymmetricKey.DES);
        SYMKEY_TYPES.put(KeyRequestResource.DESEDE_ALGORITHM, SymmetricKey.DES3);
        SYMKEY_TYPES.put(KeyRequestResource.DES3_ALGORITHM, SymmetricKey.DES3);
        SYMKEY_TYPES.put(KeyRequestResource.RC2_ALGORITHM, SymmetricKey.RC2);
        SYMKEY_TYPES.put(KeyRequestResource.RC4_ALGORITHM, SymmetricKey.RC4);
        SYMKEY_TYPES.put(KeyRequestResource.AES_ALGORITHM, SymmetricKey.AES);
    }
    private static final Map<String, KeyGenAlgorithm> SYMKEY_GEN_ALGORITHMS;
    private static final Map<String, KeyPairAlgorithm> ASYMKEY_GEN_ALGORITHMS;

    static {
        SYMKEY_GEN_ALGORITHMS = new HashMap<>();
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DES_ALGORITHM, KeyGenAlgorithm.DES);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DESEDE_ALGORITHM, KeyGenAlgorithm.DESede);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DES3_ALGORITHM, KeyGenAlgorithm.DES3);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.RC2_ALGORITHM, KeyGenAlgorithm.RC2);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.RC4_ALGORITHM, KeyGenAlgorithm.RC4);
        SYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.AES_ALGORITHM, KeyGenAlgorithm.AES);

        ASYMKEY_GEN_ALGORITHMS = new HashMap<>();
        ASYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.RSA_ALGORITHM, KeyPairAlgorithm.RSA);
        ASYMKEY_GEN_ALGORITHMS.put(KeyRequestResource.DSA_ALGORITHM, KeyPairAlgorithm.DSA);
    }
    private static final String ATTR_SERIALNO = "serialNumber";

    public KeyRequestProcessor(KRAEngine engine) {
        this.engine = engine;
        cs = engine.getConfig();
        repo = engine.getKeyRepository();
        requestRepository = engine.getRequestRepository();
        authz = engine.getAuthzSubsystem();
        auditor = engine.getAuditor();
        queue = engine.getRequestQueue();
        kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
    }

    public KeyRequestInfoCollection listRequests(Principal userPrincipal, String baseUrl, String requestState,
            String requestType, String clientKeyID, int maxTime, int start, int size, String realm) {

        logger.info("KeyRequestProcessor: Listing key requests");

        logger.debug("KeyRequestProcessor: request state: {}", requestState);
        logger.debug("KeyRequestProcessor: request type: {}", requestType);
        logger.debug("KeyRequestProcessor: client key ID: {}", clientKeyID);
        logger.debug("KeyRequestProcessor: realm: {}", realm);

        if (realm != null) {
            try {
                authz.checkRealm(realm, getAuthToken(userPrincipal), null, "certServer.kra.requests", "list");
            } catch (EAuthzAccessDenied e) {
                throw new UnauthorizedException("Not authorized to list these requests", e);
            } catch (EAuthzUnknownRealm e) {
                throw new BadRequestException("Invalid realm", e);
            } catch (EBaseException e) {
                logger.error("KeyRequestProcessor: Unable to authorize realm: " + e.getMessage(), e);
                throw new PKIException(e.toString(), e);
            }
        }

        // get ldap filter
        String filter = createSearchFilter(requestState, requestType, clientKeyID, realm);
        logger.debug("KeyRequestProcessor: filter: {}", filter);


        try {
            return listRequests(baseUrl, filter, start, size, maxTime);
        } catch (EBaseException e) {
            logger.error("KeyRequestProcessor: Unable to obtain request results: " + e.getMessage(), e);
            throw new PKIException(e.toString(), e);
        }
    }

    public KeyRequestInfo getRequestInfo(Principal userPrincipal, String baseUrl, RequestId id) {
        if (id == null) {
            logger.error("KeyRequestProcessor.getRequestInfo: id is null");
            throw new BadRequestException("Unable to get Request: invalid ID");
        }
        try {
            Request request = requestRepository.readRequest(id);
            if (request == null) {
                throw new RequestNotFoundException(id);
            }
            authz.checkRealm(request.getRealm(), getAuthToken(userPrincipal), request.getExtDataInString(Request.ATTR_REQUEST_OWNER),
                    "certServer.kra.request", "read");
            return createKeyRequestInfo(request, baseUrl);
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to get request");
        } catch (EBaseException e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public KeyRequestResponse submitRequest(Principal userPrincipal, String baseUrl, RESTMessage data) {
        Object request = null;

        try {
            Class<?> requestClazz = Class.forName(data.getClassName());
            request = requestClazz.getDeclaredConstructor(RESTMessage.class).newInstance(data);
        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | InstantiationException
                | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            throw new BadRequestException("Invalid request class." + e, e);
        }

        logger.debug("KeyRequestProcessor: Request class: {}", request.getClass().getSimpleName());
        if (request instanceof KeyArchivalRequest) {
            return archiveKey(userPrincipal, baseUrl, new KeyArchivalRequest(data));

        } else if (request instanceof KeyRecoveryRequest) {
            return recoverKey(userPrincipal, baseUrl, new KeyRecoveryRequest(data));

        } else if (request instanceof SymKeyGenerationRequest) {
            return generateSymKey(userPrincipal, baseUrl, new SymKeyGenerationRequest(data));

        } else if (request instanceof AsymKeyGenerationRequest) {
            return generateAsymKey(userPrincipal, baseUrl, new AsymKeyGenerationRequest(data));

        } else {
            throw new BadRequestException("Invalid request class.");
        }

    }

    public void approve(Principal userPrincipal, RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        if (userPrincipal == null || userPrincipal.getName() == null) {
            throw new UnauthorizedException("Request approval must be initiated by an agent");
        }
        try {
            Request request = requestRepository.readRequest(id);
            authz.checkRealm(request.getRealm(), getAuthToken(userPrincipal),
                    request.getExtDataInString(Request.ATTR_REQUEST_OWNER),
                    "certServer.kra.requests", "execute");

            kra.addAgentAsyncKeyRecovery(id.toString(), userPrincipal.getName());

            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    userPrincipal.getName(),
                    ILogger.SUCCESS,
                    id,
                    "approve"));

        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to approve request", e);
        } catch (EBaseException e) {
            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    id,
                    "approve"));
            throw new PKIException(e.toString(), e);
        }
    }

    public void reject(Principal userPrincipal, RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        if (userPrincipal == null || userPrincipal.getName() == null) {
            throw new UnauthorizedException("Request approval must be initiated by an agent");
        }
        try {
            Request request = requestRepository.readRequest(id);
            String realm = request.getRealm();
            authz.checkRealm(realm, getAuthToken(userPrincipal),
                    request.getExtDataInString(Request.ATTR_REQUEST_OWNER),
                    "certServer.kra.requests", "execute");
            request.setRequestStatus(RequestStatus.REJECTED);
            requestRepository.updateRequest(request);
            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    userPrincipal.getName(),
                    ILogger.SUCCESS,
                    id,
                    "reject"));
        }catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to reject request", e);
            //TODO: Evaluate the inclusion or not of audit log.
        } catch (EBaseException e) {
            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    id,
                    "reject"));
            throw new PKIException(e.toString(), e);
        }
    }

    public void cancel(Principal userPrincipal, RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        if (userPrincipal == null || userPrincipal.getName() == null) {
            throw new UnauthorizedException("Request approval must be initiated by an agent");
        }
        // auth and authz
        try {
            Request request = requestRepository.readRequest(id);
            String realm = request.getRealm();
            authz.checkRealm(realm, getAuthToken(userPrincipal),
                    request.getExtDataInString(Request.ATTR_REQUEST_OWNER),
                    "certServer.kra.requests", "execute");
            request.setRequestStatus(RequestStatus.CANCELED);
            requestRepository.updateRequest(request);
            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    userPrincipal.getName(),
                    ILogger.SUCCESS,
                    id,
                    "cancel"));
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to cancel request", e);
            //TODO: Evaluate the inclusion or not of audit log.
        } catch (EBaseException e) {
            e.printStackTrace();
            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    id,
                    "cancel"));
            throw new PKIException(e.toString(), e);
        }
    }

    private KeyRequestResponse generateAsymKey(Principal userPrincipal, String baseUrl, AsymKeyGenerationRequest data) {
        if (data == null) {
            throw new BadRequestException("Invalid key generation request.");
        }

        KeyRequestResponse response;
        try {
            if (userPrincipal == null || userPrincipal.getName() == null) {
                throw new UnauthorizedException("Key generation must be performed by an agent");
            }

            String realm = data.getRealm();
            if (realm != null) {
                authz.checkRealm(realm, getAuthToken(userPrincipal), null, "certServer.kra.requests.asymkey", "execute");
            }

            response = submitGenerateAsymKeyRequest(data, userPrincipal.getName(), baseUrl);
            auditor.log(new AsymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.SUCCESS,
                    response.getRequestInfo().getRequestID(),
                    data.getClientKeyId()));

            return response;
        } catch (EAuthzAccessDenied e) {
            //TODO: Evaluate the inclusion or not of audit log.
            auditor.log(new AsymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getClientKeyId()));
            throw new UnauthorizedException("Not authorized to generate request in this realm", e);
        } catch (EAuthzUnknownRealm e) {
            auditor.log(new AsymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getClientKeyId()));
            throw new BadRequestException("Invalid realm", e);
        } catch (EBaseException e) {
            auditor.log(new AsymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getClientKeyId()));
            throw new PKIException(e.toString(), e);
        }
    }

    private KeyRequestResponse generateSymKey(Principal userPrincipal, String baseUrl, SymKeyGenerationRequest data) {
        if (data == null) {
            throw new BadRequestException("Invalid key generation request.");
        }

        String realm = data.getRealm();
        KeyRequestResponse response;
        try {
            if (userPrincipal == null || userPrincipal.getName() == null) {
                throw new UnauthorizedException("Key generation must be performed by an agent");
            }

            if (realm != null) {
                authz.checkRealm(realm, getAuthToken(userPrincipal), null, "certServer.kra.requests.symkey", "execute");
            }

            response = submitGenerateSymKeyRequest(data, userPrincipal.getName(), baseUrl);

            auditor.log(new SymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.SUCCESS,
                    response.getRequestInfo().getRequestID(),
                    data.getClientKeyId()));

            return response;

        } catch (EAuthzAccessDenied e) {
            logger.error("KeyRequestService: Unauthorized access to realm " + realm, e);
            auditor.log(new SymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getClientKeyId()));
            throw new UnauthorizedException("Unauthorized access to realm " + realm, e);
            //TODO: Evaluate the inclusion or not of audit log.
        } catch (EAuthzUnknownRealm e) {
            logger.error("KeyRequestService: Unknown realm: " + realm, e);
            auditor.log(new SymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getClientKeyId()));
            throw new BadRequestException("Unknown realm: " + realm);

        } catch (EBaseException e) {
            logger.error("KeyRequestService: Unable to generate symmetric key: " + e.getMessage(), e);
            auditor.log(new SymKeyGenerationEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getClientKeyId()));
            throw new PKIException(e.toString(), e);
        }
    }

    private KeyRequestResponse recoverKey(Principal userPrincipal, String baseUrl, KeyRecoveryRequest data) {
        // auth and authz

        //Check for entirely illegal data combination here
        //Catch this before the internal server processing has to deal with it
        //If data has been provided, we need at least the wrapped session key,
        //or the command is invalid.

        if (data == null) {
            throw new BadRequestException("Invalid request.");
        }

        KeyRequestResponse response;
        try {
            response = (data.getCertificate() != null)?
                    submitAsyncKeyRecoveryRequest(data, userPrincipal.getName(), baseUrl, getAuthToken(userPrincipal)):
                    submitRecoveryRequest(data, userPrincipal.getName(), baseUrl, getAuthToken(userPrincipal));

            auditor.log(new SecurityDataRecoveryEvent(
                    userPrincipal.getName(),
                    ILogger.SUCCESS,
                    response.getRequestInfo().getRequestID(),
                    data.getKeyId(),
                    null));
            return response;

        } catch (EBaseException e) {
            auditor.log(new SecurityDataRecoveryEvent(
                    userPrincipal.getName(),
                    ILogger.FAILURE,
                    null,
                    data.getKeyId(),
                    null));
            throw new PKIException(e.toString(), e);
        }
    }

    private KeyRequestResponse archiveKey(Principal userPrincipal, String baseUrl, KeyArchivalRequest data) {
        // auth and authz
        // Catch this before internal server processing has to deal with it

        if (data == null) {
            throw new BadRequestException("Missing key archival request");
        }

        try {
            logger.debug("Request:\n {}", data.toJSON());
        } catch (JsonProcessingException e) {
            logger.error("KeyRequestProcessor: archiveKey - data not serializable to JSON");
        }

        if (data.getClientKeyId() == null || data.getDataType() == null) {
            throw new BadRequestException("Invalid key archival request.");
        }

        String algorithmOID = data.getAlgorithmOID();
        logger.info("KeyRequestProcessor: algorithm OID: " + algorithmOID);

        if (data.getWrappedPrivateData() != null) {
            if (data.getTransWrappedSessionKey() == null ||
                algorithmOID == null ||
                data.getSymmetricAlgorithmParams() == null) {
                throw new BadRequestException(
                        "Invalid key archival request.  " +
                        "Missing wrapped session key, algoriithmOIS or symmetric key parameters");
            }
        } else if (data.getPKIArchiveOptions() == null) {
            throw new BadRequestException(
                    "Invalid key archival request.  No data to archive");
        }

        String dataType = data.getDataType();
        logger.info("KeyRequestProcessor: data type: " + dataType);

        String keyAlgorithm = data.getKeyAlgorithm();
        logger.info("KeyRequestProcessor: key algorithm: " + keyAlgorithm);

        if (dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE) &&
                (keyAlgorithm == null || !SYMKEY_TYPES.containsKey(keyAlgorithm))) {
            throw new BadRequestException("Invalid symmetric key algorithm: " + keyAlgorithm);
        }

        KeyRequestResponse response;
        if (userPrincipal == null || userPrincipal.getName() == null) {
            throw new UnauthorizedException("Archival must be performed by an agent");
        }
        try {
            String realm = data.getRealm();
            if (realm != null) {
                authz.checkRealm(realm, getAuthToken(userPrincipal), null, "certServer.kra.requests.archival", "execute");
            }
            response = submitArchivalRequest(data, userPrincipal.getName(), baseUrl);

            auditor.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                    userPrincipal.getName(),
                    null,
                    response.getRequestInfo().getRequestID(),
                    data.getClientKeyId()));

            logger.debug("Response:\n {}", response.toJSON());

            return response;

        } catch (EAuthzAccessDenied e) {

            auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                    userPrincipal.getName(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));

            throw new UnauthorizedException("Not authorized to generate request in this realm", e);
            //TODO: Evaluate the inclusion or not of audit log.

        } catch (EAuthzUnknownRealm e) {

            auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                    userPrincipal.getName(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));
            throw new BadRequestException("Invalid realm", e);

        } catch (EBaseException | JsonProcessingException e) {

            auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                    userPrincipal.getName(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));

            throw new PKIException(e.toString(), e);
        }
    }

    private String createSearchFilter(String requestState, String requestType, String clientKeyID,
            String realm) {
        String filter = "";
        int matches = 0;

        if ((requestState == null) && (requestType == null) && (clientKeyID == null)) {
            filter = "(requeststate=*)";
            matches ++;
        }

        if (requestState != null) {
            filter += "(requeststate=" + LDAPUtil.escapeFilter(requestState) + ")";
            matches++;
        }

        if (requestType != null) {
            filter += "(requesttype=" + LDAPUtil.escapeFilter(requestType) + ")";
            matches++;
        }

        if (clientKeyID != null) {
            filter += "(clientID=" + LDAPUtil.escapeFilter(clientKeyID) + ")";
            matches++;
        }

        if (realm != null) {
            filter += "(realm=" + LDAPUtil.escapeFilter(realm) + ")";
            matches++;
        } else {
            filter += "(!(realm=*))";
            matches++;
        }

        if (matches > 1) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }

    private AuthToken getAuthToken(Principal principal) {
        if (principal instanceof PKIPrincipal pkiprincipal) {
            return pkiprincipal.getAuthToken();
        }
        throw new PKIException("Unable to access realm: principal not instance of PKIPrincipal");
    }

    private KeyRequestInfoCollection listRequests(String baseurl, String filter, int start, int pageSize, int maxTime) throws EBaseException {

        logger.info("KeyRequestProcessor: Searching for requests with filter {}", filter);

        KeyRequestInfoCollection keyRequestInfos = new KeyRequestInfoCollection();

        logger.debug("KeyRequestProcessor: performing paged search");

        Iterator<RequestRecord> reqs = requestRepository.searchRequest(
                filter,
                maxTime,
                start,
                pageSize + 1);

        while(reqs.hasNext()) {
            Request request = reqs.next().toRequest();
            logger.debug("- {}", request.getRequestId().toHexString());
            keyRequestInfos.addEntry(createKeyRequestInfo(request, baseurl));
        }
        keyRequestInfos.setTotal(requestRepository.getTotalRequestsByFilter(filter));
        return keyRequestInfos;
    }

    private KeyRequestInfo createKeyRequestInfo(Request request, String baseUrl) {
        KeyRequestInfo ret = new KeyRequestInfo();

        RequestId requestID = request.getRequestId();
        ret.setRequestID(requestID);

        ret.setRequestType(request.getRequestType());
        ret.setRequestStatus(request.getRequestStatus());
        if(baseUrl != null) {
            ret.setRequestURL(baseUrl + "/" + requestID);
        }
        String keyID = request.getExtDataInString("keyrecord");
        if (keyID != null && baseUrl != null) {
            // set key URL only if key ID is available
            String keysUrl = baseUrl.replace("/keyrequests", "/keys");
            ret.setKeyURL(keysUrl + "/" + keyID);
        }

        if (request.getRealm()!= null) {
            ret.setRealm(request.getRealm());
        }

        ret.setCreationTime(request.getCreationTime());
        ret.setModificationTime(request.getModificationTime());

        return ret;
    }

    private KeyRequestResponse submitArchivalRequest(KeyArchivalRequest data, String userName, String baseUrl)
            throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String wrappedSecurityData = data.getWrappedPrivateData();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();
        String algorithmOID = data.getAlgorithmOID();
        String symkeyParams = data.getSymmetricAlgorithmParams();
        String pkiArchiveOptions = data.getPKIArchiveOptions();
        String dataType = data.getDataType();
        String keyAlgorithm = data.getKeyAlgorithm();
        int keyStrength = dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE) ?
                data.getKeySize(): 0;
        String realm = data.getRealm();

        boolean keyExists = keyExists(clientKeyId, "active");

        if (keyExists) {
            throw new BadRequestException("Can not archive already active existing key!");
        }

        boolean ephemeral = kra.isEphemeral(realm);
        RequestId requestID;
        if (ephemeral) {
            requestID = createEphemeralRequestID();
        } else {
            requestID = requestRepository.createRequestID();
        }

        Request request = requestRepository.createRequest(requestID, Request.SECURITY_DATA_ENROLLMENT_REQUEST);

        if (pkiArchiveOptions != null) {
            request.setExtData(Request.REQUEST_ARCHIVE_OPTIONS, pkiArchiveOptions);
        } else {
            request.setExtData(Request.REQUEST_SECURITY_DATA, wrappedSecurityData);
            request.setExtData(Request.REQUEST_SESSION_KEY, transWrappedSessionKey);
            request.setExtData(Request.REQUEST_ALGORITHM_PARAMS, symkeyParams);
            request.setExtData(Request.REQUEST_ALGORITHM_OID, algorithmOID);
        }
        request.setExtData(Request.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);
        request.setExtData(Request.SECURITY_DATA_TYPE, dataType);
        request.setExtData(Request.SECURITY_DATA_STRENGTH,
                (keyStrength > 0) ? Integer.toString(keyStrength) : Integer.toString(0));

        if (keyAlgorithm != null) {
            request.setExtData(Request.SECURITY_DATA_ALGORITHM, keyAlgorithm);
        }

        request.setExtData(Request.ATTR_REQUEST_OWNER, userName);

        if (realm != null) {
            request.setRealm(realm);
        }

        if (!kra.isEphemeral(realm)) {
            queue.processRequest(request);
            queue.markAsServiced(request);
        } else {
            kra.processSynchronousRequest(request);
        }

        return createKeyRequestResponse(request, baseUrl);
    }

    private KeyRequestResponse submitRecoveryRequest(KeyRecoveryRequest data, String userName, String baseUrl, AuthToken authToken)
            throws EBaseException {
        Request request = createRecoveryRequest(data, userName, authToken, false);
        setTransientData(data, request);
        queue.processRequest(request);

        return createKeyRequestResponse(request, baseUrl);
    }

    private KeyRequestResponse submitAsyncKeyRecoveryRequest(KeyRecoveryRequest data, String userName,
            String baseUrl, AuthToken authToken) throws EBaseException {

        KeyId keyId = data.getKeyId();
        KeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
        } catch (DBRecordNotFoundException e) {
            throw new KeyNotFoundException(keyId, "key not found to recover", e);
        }

        String realm = rec.getRealm();
        try {
            authz.checkRealm(realm, authToken, rec.getOwnerName(), "certServer.kra.key", "recover");
        } catch (EAuthzUnknownRealm e) {
            throw new UnauthorizedException("Invalid realm", e);
        } catch (EBaseException e) {
            throw new UnauthorizedException("Agent not authorized by realm", e);
        }

        String b64Certificate = data.getCertificate();
        byte[] certData = Utils.base64decode(b64Certificate);
        String requestId = null;
        try {
            requestId = kra.initAsyncKeyRecovery(new BigInteger(keyId.toString()),
                    new X509CertImpl(certData), userName, realm);
        } catch (EBaseException | CertificateException e) {
            e.printStackTrace();
            throw new PKIException(e.toString(), e);
        }
        Request request = null;
        try {
            request = requestRepository.readRequest(new RequestId(requestId));
        } catch (EBaseException e) {
        }
        return createKeyRequestResponse(request, baseUrl);
    }

    private KeyRequestResponse submitGenerateSymKeyRequest(SymKeyGenerationRequest data, String userName, String baseUrl) throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String algName = data.getKeyAlgorithm();
        Integer keySize = data.getKeySize();
        List<String> usages = data.getUsages();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();
        String realm = data.getRealm();

        if (StringUtils.isBlank(clientKeyId)) {
            throw new BadRequestException("Invalid key generation request. Missing client ID");
        }

        boolean keyExists = keyExists(clientKeyId, "active");
        if (keyExists) {
            throw new BadRequestException("Can not archive already active existing key!");
        }

        if (keySize == null) {
            keySize = Integer.valueOf(0);
        }

        if (StringUtils.isBlank(algName)) {
            if (keySize.intValue() != 0) {
                throw new BadRequestException(
                        "Invalid request.  Must specify key algorithm if size is specified");
            }
            algName = KeyRequestResource.AES_ALGORITHM;
            keySize = Integer.valueOf(128);
        }

        KeyGenAlgorithm alg = SYMKEY_GEN_ALGORITHMS.get(algName);
        if (alg == null) {
            throw new BadRequestException("Invalid Algorithm");
        }

        if (!alg.isValidStrength(keySize.intValue())) {
            throw new BadRequestException("Invalid key size for this algorithm");
        }

        Request request = requestRepository.createRequest(Request.SYMKEY_GENERATION_REQUEST);

        request.setExtData(Request.KEY_GEN_ALGORITHM, algName);
        request.setExtData(Request.KEY_GEN_SIZE, keySize);
        request.setExtData(Request.SECURITY_DATA_STRENGTH, keySize);
        request.setExtData(Request.SECURITY_DATA_ALGORITHM, algName);

        request.setExtData(Request.KEY_GEN_USAGES, StringUtils.join(usages, ","));
        request.setExtData(Request.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);
        request.setExtData(Request.ATTR_REQUEST_OWNER, userName);

        if (transWrappedSessionKey != null) {
            request.setExtData(Request.KEY_GEN_TRANS_WRAPPED_SESSION_KEY,
                    transWrappedSessionKey);
        }

        if (realm != null) {
            request.setRealm(realm);
        }

        queue.processRequest(request);
        queue.markAsServiced(request);

        return createKeyRequestResponse(request, baseUrl);
    }

    private KeyRequestResponse submitGenerateAsymKeyRequest(AsymKeyGenerationRequest data, String userName, String baseUrl) throws EBaseException {
        String clientKeyId = data.getClientKeyId();
        String algName = data.getKeyAlgorithm();
        Integer keySize = data.getKeySize();
        List<String> usages = data.getUsages();
        String transWrappedSessionKey = data.getTransWrappedSessionKey();
        String realm = data.getRealm();

        if (StringUtils.isBlank(clientKeyId)) {
            throw new BadRequestException("Invalid key generation request. Missing client ID");
        }

        boolean keyExists = keyExists(clientKeyId, "active");
        if (keyExists) {
            throw new BadRequestException("Cannot archive already active existing key!");
        }

        if (StringUtils.isBlank(algName) && keySize.intValue() != 0) {
            throw new BadRequestException(
                    "Invalid request.  Must specify key algorithm if size is specified");
        }

        KeyPairAlgorithm alg = ASYMKEY_GEN_ALGORITHMS.get(algName);
        if (alg == null) {
            throw new BadRequestException("Unsupported algorithm specified.");
        }

        if (keySize == null) {
            if (algName.equalsIgnoreCase(KeyRequestResource.RSA_ALGORITHM)
                    || algName.equalsIgnoreCase(KeyRequestResource.DSA_ALGORITHM)) {
                throw new BadRequestException("Key size must be specified.");
            }
        } else {
            //Validate key size
            if (algName.equalsIgnoreCase(KeyRequestResource.RSA_ALGORITHM)) {
                int size = keySize;
                int minSize = cs.getInteger("keys.rsa.min.size", 256);
                int maxSize = cs.getInteger("keys.rsa.max.size", 8192);
                if (minSize > maxSize) {
                    throw new PKIException("Incorrect size parameters stored in config file.");
                }
                if (size < minSize || size > maxSize) {
                    throw new BadRequestException("Key size out of supported range - " + minSize + " - " + maxSize);
                }
                //JSS supports key sizes that are of the form 256 + (16*n), where n = 0-1008, for RSA
                if (((size - 256) % 16) != 0) {
                    throw new BadRequestException("Invalid key size specified.");
                }
            } else if (algName.equalsIgnoreCase(KeyRequestResource.DSA_ALGORITHM)) {
                // Without the PQGParams, JSS can create DSA keys of size 512, 768, 1024 only.
                String[] sizes = engine.getConfig().getString("keys.dsa.list", "512,768,1024").split(",");
                if (!Arrays.asList(sizes).contains(String.valueOf(keySize))) {
                    throw new BadRequestException("Invalid key size specified.");
                }
            }
        }

        Request request = requestRepository.createRequest(Request.ASYMKEY_GENERATION_REQUEST);

        request.setExtData(Request.KEY_GEN_ALGORITHM, algName);
        request.setExtData(Request.KEY_GEN_SIZE, keySize);
        request.setExtData(Request.SECURITY_DATA_STRENGTH, keySize);
        request.setExtData(Request.SECURITY_DATA_ALGORITHM, algName);

        request.setExtData(Request.KEY_GEN_USAGES, StringUtils.join(usages, ","));
        request.setExtData(Request.SECURITY_DATA_CLIENT_KEY_ID, clientKeyId);
        request.setExtData(Request.ATTR_REQUEST_OWNER, userName);

        if (realm != null) {
            request.setRealm(realm);
        }

        if (transWrappedSessionKey != null) {
            request.setExtData(Request.KEY_GEN_TRANS_WRAPPED_SESSION_KEY,
                    transWrappedSessionKey);
        }

        queue.processRequest(request);
        queue.markAsServiced(request);

        return createKeyRequestResponse(request, baseUrl);
    }

    private KeyRequestResponse createKeyRequestResponse(Request request, String baseUrl) {
        KeyRequestResponse response = new KeyRequestResponse();
        response.setRequestInfo(createKeyRequestInfo(request, baseUrl));
        response.setKeyData(createKeyData(request));
        return response;
    }

    private KeyData createKeyData(Request request) {
        // TODO - to be implemented when we enable one-shot generation and recovery
        // with retrieval
        return null;
    }

    private boolean keyExists(String clientKeyId, String keyStatus) throws EBaseException {

        logger.info("KeyRequestProcessor: Checking for key existence");
        logger.info("KeyRequestProcessor: - client key ID: {}", clientKeyId);
        logger.info("KeyRequestProcessor: - status: {}", keyStatus);

        String filter = "(" + KeyRecord.ATTR_CLIENT_ID + "=" + clientKeyId + ")";
        if (keyStatus != null) {
            filter = "(&" + filter + "(" + KeyRecord.ATTR_STATUS + "=" + keyStatus + "))";
        }
        logger.info("KeyRequestProcessor: - filter: {}", filter);

        Enumeration<KeyRecord> existingKeys = repo.searchKeys(filter, 1, 10);

        if (existingKeys != null && existingKeys.hasMoreElements()) {
            logger.info("KeyRequestProcessor: Key exists");
            return true;
        }

        logger.info("KeyRequestProcessor: Key does not exist");
        return false;
    }

    private RequestId createEphemeralRequestID() {

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        SecureRandom random = jssSubsystem.getRandomNumberGenerator();
        long id = System.currentTimeMillis() * 10000 + random.nextInt(10000);

        return new RequestId(id);
    }

    private Request createRecoveryRequest(KeyRecoveryRequest data, String userName,
            AuthToken authToken, boolean ephemeral) throws EBaseException{
        if (data == null) {
            throw new BadRequestException("Invalid request.");
        }

        /*if (data.getCertificate() == null &&
            data.getTransWrappedSessionKey() == null &&
            data.getSessionWrappedPassphrase() != null) {
            throw new BadRequestException("No wrapped session key.");
        }*/

        if (userName == null) {
            throw new UnauthorizedException("Recovery must be initiated by an agent");
        }

        KeyId keyId = data.getKeyId();
        KeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
        } catch (DBRecordNotFoundException e) {
            throw new KeyNotFoundException(keyId, "key not found to recover", e);
        }

        try {
            authz.checkRealm(rec.getRealm(), authToken, rec.getOwnerName(), "certServer.kra.key", "recover");
        } catch (EAuthzUnknownRealm e) {
            throw new UnauthorizedException("Invalid realm", e);
        } catch (EBaseException e) {
            throw new UnauthorizedException("Agent not authorized by realm", e);
        }

        RequestId requestID;
        if (ephemeral) {
            requestID = createEphemeralRequestID();
        } else {
            requestID = requestRepository.createRequestID();
        }

        Request request = requestRepository.createRequest(requestID, Request.SECURITY_DATA_RECOVERY_REQUEST);

        if (rec.getRealm() != null) {
            request.setRealm(rec.getRealm());
        }

        request.setExtData(ATTR_SERIALNO, keyId.toString());
        request.setExtData(Request.ATTR_REQUEST_OWNER, userName);
        request.setExtData(Request.ATTR_APPROVE_AGENTS, userName);

        String encryptOID = data.getPaylodEncryptionOID();
        if (encryptOID != null)
            request.setExtData(Request.SECURITY_DATA_PL_ENCRYPTION_OID, encryptOID);

        String wrapName = data.getPayloadWrappingName();
        if (wrapName != null)
            request.setExtData(Request.SECURITY_DATA_PL_WRAPPING_NAME, wrapName);

        return request;
    }

    private void setTransientData(KeyRecoveryRequest data, Request request) throws EBaseException {

        Hashtable<String, Object> requestParams = getTransientData(request);

        String wrappedSessionKeyStr = data.getTransWrappedSessionKey();
        String wrappedPassPhraseStr = data.getSessionWrappedPassphrase();
        String nonceDataStr = data.getNonceData();
        String encryptOID = data.getPaylodEncryptionOID();
        String wrapName = data.getPayloadWrappingName();

        if (wrappedPassPhraseStr != null) {
            requestParams.put(Request.SECURITY_DATA_SESS_PASS_PHRASE, wrappedPassPhraseStr);
        }

        if (wrappedSessionKeyStr != null) {
            requestParams.put(Request.SECURITY_DATA_TRANS_SESS_KEY, wrappedSessionKeyStr);
        }

        if (nonceDataStr != null) {
            requestParams.put(Request.SECURITY_DATA_IV_STRING_IN, nonceDataStr);
        }

        if (encryptOID != null) {
            requestParams.put(Request.SECURITY_DATA_PL_ENCRYPTION_OID, encryptOID);
        }

        if (wrapName != null) {
            requestParams.put(Request.SECURITY_DATA_PL_WRAPPING_NAME, wrapName);
        }
    }

    private Hashtable<String, Object> getTransientData(Request request) throws EBaseException {

        Hashtable<String, Object> requestParams = kra.getVolatileRequest(request.getRequestId());
        if (requestParams == null) {
            requestParams = kra.createVolatileRequest(request.getRequestId());
            if (requestParams == null) {
                throw new EBaseException("Can not create Volatile params in createRecoveryRequest!");
            }
        }
        return requestParams;
    }
}
