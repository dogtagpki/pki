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
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class KeyService extends PKIService implements KeyResource {

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

    private IKeyRepository repo;
    private IKeyRecoveryAuthority kra;
    private IRequestQueue queue;
    private IKeyService service;

    public KeyService() {
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        repo = kra.getKeyRepository();
        queue = kra.getRequestQueue();
        service = (IKeyService) kra;
    }

    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    @Override
    public Response retrieveKey(KeyRecoveryRequest data) {

        CMS.debug("KeyService.retrieveKey()");
        String auditInfo = "KeyService.retrieveKey";

        if (data == null) {
            String message = "Missing key recovery request";
            CMS.debug(message);
            auditRetrieveKey(ILogger.FAILURE, "None", "None", auditInfo + ";" + message);
            throw new BadRequestException(message);
        }

        RequestId requestID = data.getRequestId();
        CMS.debug("KeyService: request ID: " + requestID);

        if (requestID != null)
            auditInfo = auditInfo + ": requestID=" + requestID.toString();

        KeyId keyId = data.getKeyId();
        CMS.debug("KeyService: key ID: " + keyId);
        if (keyId != null)
            auditInfo = auditInfo + "; keyID=" + keyId.toString();

        IRequest request;
        try {
            request = queue.findRequest(requestID);

        } catch (EBaseException e) {
            CMS.debug(e);
            auditRetrieveKey(ILogger.FAILURE, requestID, null, auditInfo + ";" + e.getMessage());
            throw new PKIException(e.getMessage());
        }

        String type = request.getRequestType();
        CMS.debug("KeyService: request type: " + type);
        auditInfo = auditInfo + "; request type:" + type;

        KeyData keyData;
        try {
            if (IRequest.KEYRECOVERY_REQUEST.equals(type)) {
                keyData = recoverKey(data);

            } else {
                keyId = validateRequest(data);
                keyData = getKey(keyId, data);
            }

        } catch (Exception e) {
            CMS.debug(e);
            auditRetrieveKey(ILogger.FAILURE, requestID, keyId, auditInfo + ";" + e.getMessage());
            throw new PKIException(e.getMessage());
        }

        if (keyData == null) {
            CMS.debug("KeyService: No key record");
            auditRetrieveKey(ILogger.FAILURE, requestID, keyId, auditInfo + "; No key record");
            throw new HTTPGoneException("No key record.");
        }

        CMS.debug("KeyService: key retrieved");

        auditRetrieveKey(ILogger.SUCCESS, requestID, keyId, auditInfo);

        return createOKResponse(keyData);
    }

    // retrieval - used to test integration with a browser
    @Override
    public Response retrieveKey(MultivaluedMap<String, String> form) {
        String method = "KeyService.retrieveKey with form: ";
        CMS.debug(method + "begins.");
        KeyRecoveryRequest data = new KeyRecoveryRequest(form);
        return retrieveKey(data);
    }

    public KeyData getKey(KeyId keyId, KeyRecoveryRequest data) throws EBaseException {
        String method = "KeyService.getKey: ";
        String auditInfo = null;
        KeyData keyData;
        CMS.debug(method + "begins.");
        RequestId rId = data.getRequestId();

        String transWrappedSessionKey;
        String sessionWrappedPassphrase;

        IRequest request = queue.findRequest(rId);

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

        Hashtable<String, Object> requestParams = kra.getVolatileRequest(
                request.getRequestId());

        if(requestParams == null) {
            auditInfo = method + "Can't obtain Volatile requestParams in getKey!";
            CMS.debug(auditInfo);
            throw new EBaseException(auditInfo);
        }

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

            transWrappedSessionKey   = data.getTransWrappedSessionKey();
            sessionWrappedPassphrase = data.getSessionWrappedPassphrase();
            nonceData = data.getNonceData();

            if (transWrappedSessionKey == null) {
                //There must be at least a transWrappedSessionKey input provided.
                //The command AND the request have provided insufficient data, end of the line.
                auditInfo = method + "Can't retrieve key, insufficient input data!";
                CMS.debug(auditInfo);
                throw new EBaseException(auditInfo);
            }

            if (sessionWrappedPassphrase != null) {
                requestParams.put(IRequest.SECURITY_DATA_SESS_PASS_PHRASE, sessionWrappedPassphrase);
            }

            if (transWrappedSessionKey != null) {
                requestParams.put(IRequest.SECURITY_DATA_TRANS_SESS_KEY, transWrappedSessionKey);
            }

            if (nonceData != null) {
                requestParams.put(IRequest.SECURITY_DATA_IV_STRING_IN, nonceData);
            }

            try {
                // Has to be in this state or it won't go anywhere.
                request.setRequestStatus(RequestStatus.BEGIN);
                queue.processRequest(request);
            } catch (EBaseException e) {
                auditInfo = method + e.getMessage();
                kra.destroyVolatileRequest(request.getRequestId());
                throw new EBaseException(auditInfo);
            }

            nonceData = null;
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

        queue.markAsServiced(request);

        return keyData;
    }

    private KeyId validateRequest(KeyRecoveryRequest data) {
        String method = "KeyService.validateRequest: ";
        CMS.debug(method + "begins.");
        String logMessage = null;

        // confirm request exists
        RequestId reqId = data.getRequestId();
        if (reqId == null) {
            // log error
            logMessage = "Request id not found.";
            CMS.debug(logMessage);
            throw new BadRequestException(logMessage);
        }

        // confirm that at least one wrapping method exists
        // There must be at least the wrapped session key method.
        if ((data.getTransWrappedSessionKey() == null)) {
            // log error
            logMessage = "No wrapping method found.";
            CMS.debug(logMessage);

            throw new BadRequestException(logMessage);
        }

        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfo reqInfo;
        try {
            reqInfo = reqDAO.getRequest(reqId, uriInfo);
        } catch (EBaseException e1) {
            // failed to get request
            logMessage = "failed to get request";
            CMS.debug(logMessage);

            e1.printStackTrace();
            throw new PKIException(logMessage + e1.getMessage());
        }
        if (reqInfo == null) {
            // request not found
            logMessage = "No request information available.";
            CMS.debug(logMessage);

            throw new HTTPGoneException(logMessage);
        }

        //confirm request is of the right type
        String type = reqInfo.getRequestType();
        if (!type.equals(IRequest.SECURITY_DATA_RECOVERY_REQUEST)) {
            // log error
            logMessage = "Invalid request type";
            CMS.debug(logMessage);
            throw new BadRequestException(logMessage);
        }

        //confirm that retriever is originator of request, else throw 401
        String retriever = servletRequest.getUserPrincipal().getName();
        IRequest request;
        try {
            request = queue.findRequest(reqId);
        } catch (EBaseException e) {
            e.printStackTrace();
            logMessage = e.getMessage();
            CMS.debug(logMessage);

            throw new PKIException(logMessage);
        }
        String originator = request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER);
        if (! originator.equals(retriever)) {
            logMessage = "Data for recovery requests can only be retrieved by the originators of the request";
            CMS.debug(logMessage);
            throw new UnauthorizedException(logMessage);
        }

        // confirm request is in approved state
        RequestStatus status = reqInfo.getRequestStatus();
        if (!status.equals(RequestStatus.APPROVED)) {
            // log error
            logMessage = "Unauthorized request.  Recovery request not approved.";
            CMS.debug(logMessage);
            throw new UnauthorizedException(logMessage);
        }

        return reqInfo.getKeyId();
    }

    /**
     * Used to generate list of key infos based on the search parameters
     */
    @Override
    public Response listKeys(String clientKeyID, String status, Integer maxResults, Integer maxTime,
            Integer start, Integer size, String realm) {
        String method = "KeyService.listKeys: ";
        CMS.debug(method + "begins.");

        return createOKResponse(listKeyInfos(clientKeyID, status, maxResults, maxTime, start, size, realm));
    }

    public KeyInfoCollection listKeyInfos(String clientKeyID, String status, Integer maxResults, Integer maxTime,
            Integer start, Integer size, String realm) {
        String method = "KeyService.listKeyInfos: ";
        String auditInfo = "KeyService.listKeyInfos; status =" + status;
        CMS.debug(method + "begins.");

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        // get ldap filter
        String filter = createSearchFilter(status, clientKeyID, realm);
        CMS.debug("listKeys: filter is " + filter);

        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyInfoCollection infos = new KeyInfoCollection();
        try {
            Enumeration<IKeyRecord> e = repo.searchKeys(filter, maxResults, maxTime);
            if (e == null) {
                auditRetrieveKey(ILogger.SUCCESS, null, clientKeyID, auditInfo);
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
            auditRetrieveKey(ILogger.FAILURE, null, clientKeyID, e.getMessage() + auditInfo);

            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
        auditRetrieveKey(ILogger.SUCCESS, null, clientKeyID, auditInfo);

        return infos;
    }

    @Override
    public Response getActiveKeyInfo(String clientKeyID) {
        String method = "KeyService.getActiveKeyInfo: ";
        String auditInfo = "KeyService.getActiveKeyInfo";
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
                // return the first one
                auditRetrieveKey(ILogger.SUCCESS, null, clientKeyID, auditInfo);

                return createOKResponse(info);
            }
        }
        String message = "Key not found.";
        auditRetrieveKey(ILogger.FAILURE, null, clientKeyID, message + auditInfo);

        throw new ResourceNotFoundException(auditInfo + ":" + message);
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

    public void auditRetrieveKey(String status, RequestId requestID, KeyId keyID, String reason) {
        auditRetrieveKey(status, requestID != null ? requestID.toString(): "null",
                keyID != null ? keyID.toString(): "null", reason);
    }

    public void auditRetrieveKey(String status, String requestID, String keyID, String reason) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_RETRIEVE_KEY,
                servletRequest.getUserPrincipal().getName(),
                status,
                requestID,
                keyID,
                reason);
        auditor.log(msg);
    }

    public void auditKeyStatusChange(String status, String keyID, String oldKeyStatus, String newKeyStatus, String info) {
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
        String auditInfo = "KeyService.recoverKey";
        CMS.debug(method + "begins.");

        // confirm request exists
        RequestId reqId = data.getRequestId();

        IRequest request = null;
        try {
            request = queue.findRequest(reqId);
        } catch (EBaseException e) {
        }
        if (request == null) {
            auditInfo = method + "No request record.";
            throw new HTTPGoneException(auditInfo);
        }
        String type = request.getRequestType();
        RequestStatus status = request.getRequestStatus();
        if (!IRequest.KEYRECOVERY_REQUEST.equals(type) ||
            !status.equals(RequestStatus.APPROVED)) {
            auditInfo = method + "Unauthorized request.";
            throw new UnauthorizedException(auditInfo);
        }

        String passphrase = data.getPassphrase();
        byte pkcs12[] = null;
        try {
            pkcs12 = service.doKeyRecovery(reqId.toString(), passphrase);
        } catch (EBaseException e) {
        }
        if (pkcs12 == null) {
            auditInfo = method + "pkcs12 null; Key not recovered.";
            throw new HTTPGoneException(auditInfo);
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
        String method = "KeyService.getKeyInfo: ";
        String auditInfo = "KeyService.getKeyInfo";
        CMS.debug(method + "begins.");

        IKeyRecord rec = null;
        try {
            rec = repo.readKeyRecord(keyId.toBigInteger());
            KeyInfo info = createKeyDataInfo(rec, true);
            auditRetrieveKey(ILogger.SUCCESS, null, keyId, auditInfo);

            return createOKResponse(info);
        } catch (EDBRecordNotFoundException e) {
            auditInfo = method + e.getMessage();
            auditRetrieveKey(ILogger.FAILURE, null, keyId, auditInfo);

            throw new KeyNotFoundException(keyId);
        } catch (Exception e) {
            auditInfo = method + "Unable to retrieve key record: " + e.getMessage();
            auditRetrieveKey(ILogger.FAILURE, null, keyId, auditInfo);
            CMS.debug(auditInfo);
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response modifyKeyStatus(KeyId keyId, String status) {
        String method = "KeyService.modifyKeyStatus: ";
        //TODO: what was the original status?  find it and record that in Info as well
        String auditInfo = "KeyService.modifyKeyStatus";

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
            throw new KeyNotFoundException(keyId);
        } catch (Exception e) {
            auditInfo = auditInfo + ":" + e.getMessage();
            CMS.debug(auditInfo);
            auditKeyStatusChange(ILogger.FAILURE, keyId.toString(),
                    (info!=null)?info.getStatus():null, status, auditInfo);
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }


}
