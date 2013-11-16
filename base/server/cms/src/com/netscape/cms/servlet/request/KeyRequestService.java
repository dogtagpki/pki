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

package com.netscape.cms.servlet.request;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfos;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class KeyRequestService extends PKIService implements KeyRequestResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    private static final String LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_4";

    private static final String LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_4";

    private static final String LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_STATE_CHANGE =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_STATE_CHANGE_4";

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    private IKeyRecoveryAuthority kra;
    private IRequestQueue queue;
    private IKeyService service;

    public KeyRequestService() {
        kra = ( IKeyRecoveryAuthority ) CMS.getSubsystem( "kra" );
        queue = kra.getRequestQueue();
        service = (IKeyService) kra;
    }

    /**
     * Used to retrieve key request info for a specific request
     */
    @Override
    public KeyRequestInfo getRequestInfo(RequestId id) {
        if (id == null) {
            CMS.debug("getRequestInfo: is is null");
            throw new BadRequestException("Unable to get Request: invalid ID");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.getRequest(id, uriInfo);
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
        }
        return info;
    }

    // Archiving - used to test integration with a browser
    @Override
    public Response archiveKey(MultivaluedMap<String, String> form) {
        KeyArchivalRequest data = new KeyArchivalRequest(form);
        return archiveKey(data);
    }

    @Override
    public Response archiveKey(KeyArchivalRequest data) {
        // auth and authz
        // Catch this before internal server processing has to deal with it

        if (data == null || data.getClientId() == null
                || data.getWrappedPrivateData() == null
                || data.getDataType() == null) {
            throw new BadRequestException("Invalid key archival request.");
        }

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.submitRequest(data, uriInfo);
            auditArchivalRequestMade(info.getRequestId(), ILogger.SUCCESS, data.getClientId());

            return Response
                    .created(new URI(info.getRequestURL()))
                    .entity(info)
                    .type(MediaType.APPLICATION_XML)
                    .build();
        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditArchivalRequestMade(null, ILogger.FAILURE, data.getClientId());
            throw new PKIException(e.toString());
        }
    }

    //Recovery - used to test integration with a browser
    @Override
    public Response recoverKey(MultivaluedMap<String, String> form) {
        KeyRecoveryRequest data = new KeyRecoveryRequest(form);
        return recoverKey(data);
    }

    @Override
    public Response recoverKey(KeyRecoveryRequest data) {
        // auth and authz

        //Check for entirely illegal data combination here
        //Catch this before the internal server processing has to deal with it
        //If data has been provided, we need at least the wrapped session key,
        //or the command is invalid.

        if (data == null) {
            throw new BadRequestException("Invalid request.");
        }
        if (data.getCertificate() == null &&
            data.getTransWrappedSessionKey() == null &&
            data.getSessionWrappedPassphrase() != null) {
            throw new BadRequestException("No wrapped session key.");
        }
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = (data.getCertificate() != null)?
                    requestKeyRecovery(data): dao.submitRequest(data, uriInfo);
            auditRecoveryRequestMade(info.getRequestId(), ILogger.SUCCESS, data.getKeyId());

            return Response
                    .created(new URI(info.getRequestURL()))
                    .entity(info)
                    .type(MediaType.APPLICATION_XML)
                    .build();
        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditRecoveryRequestMade(null, ILogger.FAILURE, data.getKeyId());
            throw new PKIException(e.toString());
        }
    }

    private KeyRequestInfo requestKeyRecovery(KeyRecoveryRequest data) {
        KeyRequestInfo info = null;
        if (data == null) {
            throw new BadRequestException("Invalid request.");
        }
        String keyId = data.getKeyId().toString();
        String b64Certificate = data.getCertificate();
        byte[] certData = Utils.base64decode(b64Certificate);
        String agentID = servletRequest.getUserPrincipal().getName();
        String requestId = null;
        try {
            requestId = service.initAsyncKeyRecovery(new BigInteger(keyId), new X509CertImpl(certData), agentID);
        } catch (EBaseException | CertificateException e) {
            e.printStackTrace();
            throw new PKIException(e.toString());
        }
        IRequest request = null;
        try {
            request = queue.findRequest(new RequestId(requestId));
        } catch (EBaseException e) {
        }
        KeyRequestDAO dao = new KeyRequestDAO();
        info = dao.createCMSRequestInfo(request, uriInfo);

        return info;
    }

    @Override
    public void approveRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            IRequest request = queue.findRequest(id);
            String type = request.getRequestType();
            if (IRequest.KEYRECOVERY_REQUEST.equals(type)) {
                service.addAgentAsyncKeyRecovery(id.toString(), servletRequest.getUserPrincipal().getName());
                auditRecoveryRequestChange(id, ILogger.SUCCESS, "approve");
            } else if (IRequest.SECURITY_DATA_RECOVERY_REQUEST.equals(type)) {
                dao.approveRequest(id);
                auditRecoveryRequestChange(id, ILogger.SUCCESS, "approve");
            }
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "approve");
            throw new PKIException(e.toString());
        }
    }

    @Override
    public void rejectRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.rejectRequest(id);
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "reject");
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "reject");
            throw new PKIException(e.toString());
        }
    }

    @Override
    public void cancelRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.cancelRequest(id);
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "cancel");
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "cancel");
            throw new PKIException(e.toString());
        }
    }

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @Override
    public KeyRequestInfos listRequests(String requestState, String requestType, String clientID,
            RequestId start, Integer pageSize, Integer maxResults, Integer maxTime) {
        // auth and authz

        // get ldap filter
        String filter = createSearchFilter(requestState, requestType, clientID);
        CMS.debug("listRequests: filter is " + filter);

        start = start == null ? new RequestId(KeyRequestService.DEFAULT_START) : start;
        pageSize = pageSize == null ? DEFAULT_PAGESIZE : pageSize;
        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfos requests;
        try {
            requests = reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            CMS.debug("listRequests: error in obtaining request results" + e);
            e.printStackTrace();
            throw new PKIException(e.toString());
        }
        return requests;
    }

    private String createSearchFilter(String requestState, String requestType, String clientID) {
        String filter = "";
        int matches = 0;

        if ((requestState == null) && (requestType == null) && (clientID == null)) {
            filter = "(requeststate=*)";
            return filter;
        }

        if (requestState != null) {
            filter += "(requeststate=" + LDAPUtil.escapeFilter(requestState) + ")";
            matches ++;
        }

        if (requestType != null) {
            filter += "(requesttype=" + LDAPUtil.escapeFilter(requestType) + ")";
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

    public void auditRecoveryRequestChange(RequestId requestId, String status, String operation) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_STATE_CHANGE,
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId.toString(),
                operation);
        auditor.log(msg);
    }

    public void auditRecoveryRequestMade(RequestId requestId, String status, KeyId dataId) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST,
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId != null? requestId.toString(): "null",
                dataId.toString());
        auditor.log(msg);
    }

    public void auditArchivalRequestMade(RequestId requestId, String status, String clientId) {
        String msg = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST,
                servletRequest.getUserPrincipal().getName(),
                status,
                requestId != null? requestId.toString(): "null",
                clientId);
        auditor.log(msg);
    }
}
