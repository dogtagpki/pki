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

package com.netscape.cms.servlet.key;


import java.math.BigInteger;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.HTTPGoneException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyDataInfo;
import com.netscape.certsrv.key.KeyDataInfos;
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

    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;
    public final static int DEFAULT_SIZE = 20;

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
    public KeyData retrieveKey(KeyRecoveryRequest data) {
        if (data == null) {
            CMS.debug("retrieveKey: data is null");
            throw new BadRequestException("Cannot retrieve key. Invalid request");
        }
        // auth and authz
        RequestId requestID = data.getRequestId();
        IRequest request;
        try {
            request = queue.findRequest(requestID);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRetrieveKey(ILogger.FAILURE, requestID, null, e.getMessage());
            throw new PKIException(e.getMessage());
        }
        String type = request.getRequestType();
        KeyId keyId = null;
        KeyData keyData;
        try {
            if (IRequest.KEYRECOVERY_REQUEST.equals(type)) {
                keyData = recoverKey(data);
            } else {
                keyId = validateRequest(data);
                keyData = getKey(keyId, data);
            }
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRetrieveKey(ILogger.FAILURE, requestID, keyId, e.getMessage());
            throw new PKIException(e.getMessage());
        }
        if (keyData == null) {
            // no key record
            auditRetrieveKey(ILogger.FAILURE, requestID, keyId, "No key record");
            throw new HTTPGoneException("No key record.");
        }
        auditRetrieveKey(ILogger.SUCCESS, requestID, keyId, "None");
        return keyData;
    }

    // retrieval - used to test integration with a browser
    @Override
    public KeyData retrieveKey(MultivaluedMap<String, String> form) {
        KeyRecoveryRequest data = new KeyRecoveryRequest(form);
        return retrieveKey(data);
    }

    public KeyData getKey(KeyId keyId, KeyRecoveryRequest data) throws EBaseException {
        KeyData keyData;

        RequestId rId = data.getRequestId();

        String transWrappedSessionKey;
        String sessionWrappedPassphrase;

        IRequest request = queue.findRequest(rId);

        if (request == null) {
            return null;
        }

     // get wrapped key
        IKeyRecord rec = repo.readKeyRecord(keyId.toBigInteger());
        if (rec == null) {
            return null;
        }

        Hashtable<String, Object> requestParams = kra.getVolatileRequest(
                request.getRequestId());

        if(requestParams == null) {
            auditRetrieveKey(ILogger.FAILURE, rId, keyId, "cannot obtain volatile requestParams");
            throw new EBaseException("Can't obtain Volatile requestParams in getKey!");
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
                auditRetrieveKey(ILogger.FAILURE, rId, keyId, "insufficient input data");
                throw new EBaseException("Can't retrieve key, insufficient input data!");
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
                kra.destroyVolatileRequest(request.getRequestId());
                throw new EBaseException(e.toString());
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

        kra.destroyVolatileRequest(request.getRequestId());

        queue.markAsServiced(request);

        return keyData;
    }

    private KeyId validateRequest(KeyRecoveryRequest data) {

        // confirm request exists
        RequestId reqId = data.getRequestId();
        if (reqId == null) {
            auditRetrieveKey(ILogger.FAILURE, null, null, "Request id not found");
            // log error
            throw new BadRequestException("Request id not found.");
        }

        // confirm that at least one wrapping method exists
        // There must be at least the wrapped session key method.
        if ((data.getTransWrappedSessionKey() == null)) {
            auditRetrieveKey(ILogger.FAILURE, reqId, null, "No wrapping method found");
            // log error
            throw new BadRequestException("No wrapping method found.");
        }

        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfo reqInfo;
        try {
            reqInfo = reqDAO.getRequest(reqId, uriInfo);
        } catch (EBaseException e1) {
            auditRetrieveKey(ILogger.FAILURE, reqId, null, "failed to get request");
            // failed to get request
            e1.printStackTrace();
            throw new PKIException(e1.getMessage());
        }
        if (reqInfo == null) {
            auditRetrieveKey(ILogger.FAILURE, reqId, null, "no request info available");
            // request not found
            throw new HTTPGoneException("No request information available.");
        }

        //confirm request is of the right type
        String type = reqInfo.getRequestType();
        if (!type.equals(IRequest.SECURITY_DATA_RECOVERY_REQUEST)) {
            auditRetrieveKey(ILogger.FAILURE, reqId, null, "invalid request type");
            // log error
            throw new BadRequestException("Invalid request type");
        }

        //confirm that agent is originator of request, else throw 401
        //  TO-DO

        // confirm request is in approved state
        RequestStatus status = reqInfo.getRequestStatus();
        if (!status.equals(RequestStatus.APPROVED)) {
            auditRetrieveKey(ILogger.FAILURE, reqId, null, "recovery request not approved");
            // log error
            throw new UnauthorizedException("Unauthorized request.  Recovery request not approved.");
        }

        return reqInfo.getKeyId();
    }

    /**
     * Used to generate list of key infos based on the search parameters
     */
    @Override
    public KeyDataInfos listKeys(String clientID, String status, Integer maxResults, Integer maxTime,
            Integer start, Integer size) {

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        // get ldap filter
        String filter = createSearchFilter(status, clientID);
        CMS.debug("listKeys: filter is " + filter);

        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyDataInfos infos = new KeyDataInfos();
        try {
            Enumeration<IKeyRecord> e = repo.searchKeys(filter, maxResults, maxTime);
            if (e == null) {
                return infos;
            }

            // store non-null results in a list
            List<KeyDataInfo> results = new ArrayList<KeyDataInfo>();
            while (e.hasMoreElements()) {
                IKeyRecord rec = e.nextElement();
                if (rec == null) continue;
                results.add(createKeyDataInfo(rec));
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
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        return infos;
    }


    public KeyDataInfo createKeyDataInfo(IKeyRecord rec) throws EBaseException {
        KeyDataInfo ret = new KeyDataInfo();
        ret.setClientID(rec.getClientId());
        ret.setStatus(rec.getKeyStatus());
        ret.setAlgorithm(rec.getAlgorithm());
        ret.setSize(rec.getKeySize());
        ret.setOwnerName(rec.getOwnerName());

        Path keyPath = KeyResource.class.getAnnotation(Path.class);
        BigInteger serial = rec.getSerialNumber();

        UriBuilder keyBuilder = uriInfo.getBaseUriBuilder();
        keyBuilder.path(keyPath.value() + "/" + serial);
        ret.setKeyURL(keyBuilder.build().toString());

        return ret;
    }

    private String createSearchFilter(String status, String clientID) {
        String filter = "";
        int matches = 0;

        if ((status == null) && (clientID == null)) {
            filter = "(serialno=*)";
            return filter;
        }

        if (status != null) {
            filter += "(status=" + LDAPUtil.escapeFilter(status) + ")";
            matches ++;
        }

        if (clientID != null) {
            filter += "(clientID=" + LDAPUtil.escapeFilter(clientID) + ")";
            matches ++;
        }

        if (matches > 1) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }

    public void auditRetrieveKey(String status, RequestId requestID, KeyId keyID, String reason) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_RETRIEVE_KEY,
                servletRequest.getUserPrincipal().getName(),
                status,
                requestID != null ? requestID.toString(): "null",
                keyID != null ? keyID.toString(): "null",
                reason);
        auditor.log(msg);
    }

    /**
     * Used to retrieve a key
     * @param data
     * @return
     */
    private KeyData recoverKey(KeyRecoveryRequest data) {
        // confirm request exists
        RequestId reqId = data.getRequestId();

        IRequest request = null;
        try {
            request = queue.findRequest(reqId);
        } catch (EBaseException e) {
        }
        if (request == null) {
            throw new HTTPGoneException("No request record.");
        }
        String type = request.getRequestType();
        RequestStatus status = request.getRequestStatus();
        if (!IRequest.KEYRECOVERY_REQUEST.equals(type) ||
            !status.equals(RequestStatus.APPROVED)) {
            auditRetrieveKey(ILogger.FAILURE, reqId, null, "Unauthorized request.");
            throw new UnauthorizedException("Unauthorized request.");
        }

        String passphrase = data.getPassphrase();
        byte pkcs12[] = null;
        try {
            pkcs12 = service.doKeyRecovery(reqId.toString(), passphrase);
        } catch (EBaseException e) {
        }
        if (pkcs12 == null) {
            throw new HTTPGoneException("Key not recovered.");
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
}
