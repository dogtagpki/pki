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

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.HTTPGoneException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.EDBRecordNotFoundException;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.certsrv.key.KeyNotFoundException;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class KeyService extends SubsystemService implements KeyResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    private final static String LOGGING_SIGNED_AUDIT_SECURITY_DATA_RETRIEVE_KEY =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RETRIEVE_KEY_5";
    private final static String LOGGING_SIGNED_AUDIT_KEY_STATUS_CHANGE =
            "LOGGING_SIGNED_AUDIT_KEY_STATUS_CHANGE_6";

    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;
    public static final String ATTR_SERIALNO = "serialNumber";

    private IKeyRepository repo;
    private IKeyRecoveryAuthority kra;
    private IRequestQueue queue;
    private IKeyService service;

    //parameters for auditing
    private RequestId requestId;
    private KeyId keyId;
    private String auditInfo;

    public KeyService() {
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        repo = kra.getKeyRepository();
        queue = kra.getRequestQueue();
        service = (IKeyService) kra;
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
        try {
            return retrieveKeyImpl(data);
        } catch(RuntimeException e) {
            auditError(e.getMessage());
            throw e;
        } catch (Exception e) {
            auditError(e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Response retrieveKeyImpl(KeyRecoveryRequest data) {
        boolean synchronous = false;
        boolean ephemeral = false;
        String realm = null;

        auditInfo = "KeyService.retrieveKey";
        CMS.debug(auditInfo);

        if (data == null) {
            throw new BadRequestException("Missing key Recovery Request");
        }

        // get or create request
        IRequest request = null;
        requestId = data.getRequestId();
        if (requestId != null) {
            // this is an asynchronous request
            // We assume that the request is valid and has been approved
            CMS.debug("KeyService: request ID: " + requestId);
            auditInfo += ";requestID=" + requestId.toString();

            try {
                request = queue.findRequest(requestId);
            } catch (EBaseException e) {
                throw new PKIException(e.getMessage(), e);
            }

            if (request == null) {
                throw new BadRequestException("No request found");
            }

            keyId = new KeyId(request.getExtDataInString(ATTR_SERIALNO));
            auditInfo += ";keyID=" + keyId.toString();

            data.setKeyId(keyId);
        } else {
            keyId = data.getKeyId();
            if (keyId == null) {
                throw new BadRequestException("Missing key Recovery Request");
            }

            auditInfo += ";keyID=" + keyId.toString();

            // TODO(alee): get the realm from the key record
            synchronous = kra.isRetrievalSynchronous(realm);
            ephemeral = kra.isEphemeral(realm);

            // Only synchronous requests can be ephemeral
            if (!synchronous) ephemeral = false;

            auditInfo += ";synchronous=" + Boolean.toString(synchronous);
            auditInfo += ";ephemeral=" + Boolean.toString(ephemeral);

            KeyRequestDAO reqDAO = new KeyRequestDAO();
            try {
                request = reqDAO.createRecoveryRequest(data, uriInfo, getRequestor(),
                        getAuthToken(), ephemeral);
            } catch (EBaseException e) {
                throw new PKIException(e.getMessage(), e);
            }

            requestId = request.getRequestId();
            auditInfo += ";requestID=" + requestId.toString();

            if (!synchronous) {
                // store the request in LDAP
                try {
                    queue.updateRequest(request);
                } catch (EBaseException e) {
                    e.printStackTrace();
                    throw new PKIException(e.getMessage(), e);
                }

                CMS.debug("Returning created recovery request");
                auditRetrieveKey(ILogger.SUCCESS, "Created recovery request");

                KeyData keyData = new KeyData();
                keyData.setRequestID(requestId);
                return createOKResponse(keyData);
            }
        }

        data.setRequestId(requestId);

        String type = request.getRequestType();
        CMS.debug("KeyService: request type: " + type);
        auditInfo += ";request type:" + type;

        // process request
        KeyData keyData = null;
        try {
            switch(type) {
                case IRequest.KEYRECOVERY_REQUEST:
                    keyData = recoverKey(data);
                    break;
                case IRequest.SECURITY_DATA_RECOVERY_REQUEST:
                    if (synchronous)  request.setRequestStatus(RequestStatus.APPROVED);
                    validateRequest(data, request);
                    keyData = getKey(keyId, request, data, synchronous, ephemeral);
                    break;
                default:
                    throw new BadRequestException("Invalid request type: " + type);
            }
        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }

        if (keyData == null) {
            throw new HTTPGoneException("No key record.");
        }

        CMS.debug("KeyService: key retrieved");
        auditRetrieveKey(ILogger.SUCCESS);
        return createOKResponse(keyData);
    }

    // retrieval - used to test integration with a browser
    @Override
    public Response retrieveKey(MultivaluedMap<String, String> form) {
        CMS.debug("KeyService.retrieveKey with form: begins.");
        KeyRecoveryRequest data = new KeyRecoveryRequest(form);
        return retrieveKey(data);
    }

    public KeyData getKey(KeyId keyId, IRequest request, KeyRecoveryRequest data,
            boolean synchronous, boolean ephemeral) throws EBaseException {
        String method = "KeyService.getKey:";
        auditInfo = method;
        KeyData keyData;
        KeyRequestDAO dao = new KeyRequestDAO();
        CMS.debug(method + "begins.");

        if (data == null) {
            CMS.debug(method + "KeyRecoveryRequest is null");
            return null;
        }

        if (request == null) {
            CMS.debug(method + "request null");
            return null;
        }

        // get wrapped key
        IKeyRecord rec = repo.readKeyRecord(keyId.toBigInteger());
        if (rec == null) {
            CMS.debug(method + "key record null");
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

        String algorithm = rec.getAlgorithm();
        Integer keySize = rec.getKeySize();

        if (algorithm != null) {
            keyData.setAlgorithm(algorithm);
        }

        if (keySize != null) {
            keyData.setSize(keySize);
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
        CMS.debug(method + "begins.");

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
        CMS.debug("KeyService.listKeys: begins.");
        try {
            return createOKResponse(listKeyInfos(clientKeyID, status, maxResults, maxTime, start, size, realm));
        } catch (RuntimeException e) {
            auditError(e.getMessage());
            throw e;
        } catch (Exception e) {
            auditError(e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }
    }

    public KeyInfoCollection listKeyInfos(String clientKeyID, String status, Integer maxResults, Integer maxTime,
            Integer start, Integer size, String realm) {
        String method = "KeyService.listKeyInfos: ";
        auditInfo = "KeyService.listKeyInfos; status =" + status;
        CMS.debug(method + "begins.");

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        if (realm != null) {
            try {
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.keys", "list");
            } catch (EAuthzAccessDenied e) {
                throw new UnauthorizedException("Not authorized to list these keys", e);
            } catch (EAuthzUnknownRealm e) {
                throw new BadRequestException("Invalid realm", e);
            } catch (EBaseException e) {
                CMS.debug("listRequests: unable to authorize realm" + e);
                throw new PKIException(e.toString(), e);
            }
        }

        // get ldap filter
        String filter = createSearchFilter(status, clientKeyID, realm);
        CMS.debug("listKeys: filter is " + filter);

        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyInfoCollection infos = new KeyInfoCollection();
        try {
            Enumeration<IKeyRecord> e = repo.searchKeys(filter, maxResults, maxTime);
            if (e == null) {
                auditRetrieveKey(ILogger.SUCCESS);
                return infos;
            }

            // store non-null results in a list
            List<KeyInfo> results = new ArrayList<KeyInfo>();
            while (e.hasMoreElements()) {
                IKeyRecord rec = e.nextElement();
                if (rec == null) continue;
                results.add(createKeyDataInfo(rec, false));
            }

            int total = results.size();
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
            throw new PKIException(e.getMessage(), e);
        }
        auditRetrieveKey(ILogger.SUCCESS);

        return infos;
    }

    @Override
    public Response getActiveKeyInfo(String clientKeyID) {
        try {
            return getActiveKeyInfoImpl(clientKeyID);
        } catch (RuntimeException e) {
            auditError(e.getMessage());
            throw e;
        } catch (Exception e) {
            auditError(e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Response getActiveKeyInfoImpl(String clientKeyID) {
        String method = "KeyService.getActiveKeyInfo: ";
        auditInfo = "KeyService.getActiveKeyInfo";
        CMS.debug(method + "begins.");

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
                    CMS.debug("listRequests: unable to authorize realm" + e);
                    throw new PKIException(e.toString(), e);
                }

                auditRetrieveKey(ILogger.SUCCESS);

                return createOKResponse(info);
            }
        }
        throw new ResourceNotFoundException("Key not found");
    }

    public KeyInfo createKeyDataInfo(IKeyRecord rec, boolean getPublicKey) throws EBaseException {
        String method = "KeyService.createKeyDataInfo: ";
        CMS.debug(method + "begins.");

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
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_RETRIEVE_KEY,
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId != null ? requestId.toString(): "null",
                keyId != null ? keyId.toString(): "null",
                (reason != null) ? auditInfo + ";" + reason : auditInfo
        );
        auditor.log(msg);
    }

    public void auditRetrieveKey(String status) {
        auditRetrieveKey(status, null);
    }

    public void auditError(String message) {
        CMS.debug(message);
        auditRetrieveKey(ILogger.FAILURE, message);
    }

    public void auditKeyStatusChange(String status, String keyID, String oldKeyStatus,
            String newKeyStatus, String info) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_KEY_STATUS_CHANGE,
                servletRequest.getUserPrincipal().getName(),
                status,
                keyID,
                oldKeyStatus,
                newKeyStatus,
                info);
        auditor.log(msg);
    }

    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    private KeyData recoverKey(KeyRecoveryRequest data) throws UnauthorizedException, HTTPGoneException {
        String method = "KeyService.recoverKey: ";
        auditInfo = "KeyService.recoverKey";
        CMS.debug(method + "begins.");

        // confirm request exists
        RequestId reqId = data.getRequestId();

        IRequest request = null;
        try {
            request = queue.findRequest(reqId);
        } catch (EBaseException e) {
        }
        if (request == null) {
            throw new HTTPGoneException("No request record");
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
            throw new PKIException("Cannot set transient data", e);
        }

        String passphrase = data.getPassphrase();
        byte pkcs12[] = null;
        try {
            pkcs12 = service.doKeyRecovery(reqId.toString(), passphrase);
        } catch (EBaseException e) {
        }
        if (pkcs12 == null) {
            throw new HTTPGoneException("pkcs12 null; Key not recovered");
        }
        String pkcs12base64encoded = Utils.base64encode(pkcs12);

        KeyData keyData = new KeyData();
        keyData.setP12Data(pkcs12base64encoded);

        try {
            queue.processRequest(request);
            queue.markAsServiced(request);
        } catch (EBaseException e) {
        }

        return keyData;
    }

    @Override
    public Response getKeyInfo(KeyId keyId) {
        try {
            return getKeyInfoImpl(keyId);
        } catch (RuntimeException e) {
            auditError(e.getMessage());
            throw e;
        } catch (Exception e) {
            auditError(e.getMessage());
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Response getKeyInfoImpl(KeyId keyId) {
        String method = "KeyService.getKeyInfo: ";
        auditInfo = "KeyService.getKeyInfo";
        CMS.debug(method + "begins.");

        IKeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
            authz.checkRealm(rec.getRealm(), getAuthToken(), rec.getOwnerName(), "certServer.kra.key", "read");
            KeyInfo info = createKeyDataInfo(rec, true);
            auditRetrieveKey(ILogger.SUCCESS);

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

        CMS.debug(method + "begins.");
        IKeyRecord rec = null;
        KeyInfo info = null;
        try {

            rec = repo.readKeyRecord(keyId.toBigInteger());
            info = createKeyDataInfo(rec, true); // for getting the old status for auditing purpose

            ModificationSet mods = new ModificationSet();
            mods.add(IKeyRecord.ATTR_STATUS, Modification.MOD_REPLACE,
                    status);
            repo.modifyKeyRecord(keyId.toBigInteger(), mods);
            auditKeyStatusChange(ILogger.SUCCESS, keyId.toString(),
                    (info!=null)?info.getStatus():null, status, auditInfo);

            return createNoContentResponse();
        } catch (EDBRecordNotFoundException e) {
            auditInfo = auditInfo + ":" + e.getMessage();
            CMS.debug(auditInfo);
            auditKeyStatusChange(ILogger.FAILURE, keyId.toString(),
                    (info!=null)?info.getStatus():null, status, auditInfo);
            throw new KeyNotFoundException(keyId, "key not found to modify", e);
        } catch (Exception e) {
            auditInfo = auditInfo + ":" + e.getMessage();
            CMS.debug(auditInfo);
            auditKeyStatusChange(ILogger.FAILURE, keyId.toString(),
                    (info!=null)?info.getStatus():null, status, auditInfo);
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    private String getRequestor() {
        return servletRequest.getUserPrincipal().getName();
    }

}
