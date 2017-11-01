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

import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyArchivalRequest;
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
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class KeyRequestService extends SubsystemService implements KeyRequestResource {

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    public static final Map<String, SymmetricKey.Type> SYMKEY_TYPES;
    static {
        SYMKEY_TYPES = new HashMap<String, SymmetricKey.Type>();
        SYMKEY_TYPES.put(KeyRequestResource.DES_ALGORITHM, SymmetricKey.DES);
        SYMKEY_TYPES.put(KeyRequestResource.DESEDE_ALGORITHM, SymmetricKey.DES3);
        SYMKEY_TYPES.put(KeyRequestResource.DES3_ALGORITHM, SymmetricKey.DES3);
        SYMKEY_TYPES.put(KeyRequestResource.RC2_ALGORITHM, SymmetricKey.RC2);
        SYMKEY_TYPES.put(KeyRequestResource.RC4_ALGORITHM, SymmetricKey.RC4);
        SYMKEY_TYPES.put(KeyRequestResource.AES_ALGORITHM, SymmetricKey.AES);
    }

    /**
     * Used to retrieve key request info for a specific request
     */
    @Override
    public Response getRequestInfo(RequestId id) {
        if (id == null) {
            CMS.debug("getRequestInfo: is is null");
            throw new BadRequestException("Unable to get Request: invalid ID");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.getRequest(id, uriInfo, getAuthToken());
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to get request");
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
        }
        return createOKResponse(info);
    }

    public Response archiveKey(KeyArchivalRequest data) {
        // auth and authz
        // Catch this before internal server processing has to deal with it

        if (data == null || data.getClientKeyId() == null || data.getDataType() == null) {
            throw new BadRequestException("Invalid key archival request.");
        }

        if (data.getWrappedPrivateData() != null) {
            if (data.getTransWrappedSessionKey() == null ||
                data.getAlgorithmOID() == null ||
                data.getSymmetricAlgorithmParams() == null) {
                throw new BadRequestException(
                        "Invalid key archival request.  " +
                        "Missing wrapped session key, algoriithmOIS or symmetric key parameters");
            }
        } else if (data.getPKIArchiveOptions() == null) {
            throw new BadRequestException(
                    "Invalid key archival request.  No data to archive");
        }

        if (data.getDataType().equals(KeyRequestResource.SYMMETRIC_KEY_TYPE)) {
            if ((data.getKeyAlgorithm() == null) ||
                (! SYMKEY_TYPES.containsKey(data.getKeyAlgorithm()))) {
                throw new BadRequestException("Invalid key archival request.  Bad algorithm.");
            }
        }

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            if (getRequestor() == null) {
                throw new UnauthorizedException("Archival must be performed by an agent");
            }

            String realm = data.getRealm();
            if (realm != null) {
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests.archival", "execute");
            }
            response = dao.submitRequest(data, uriInfo, getRequestor());

            audit(SecurityDataArchivalRequestEvent.createSuccessEvent(
                    getRequestor(),
                    null,
                    response.getRequestInfo().getRequestId(),
                    data.getClientKeyId()));

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));

        } catch (EAuthzAccessDenied e) {

            audit(SecurityDataArchivalRequestEvent.createFailureEvent(
                    getRequestor(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));

            throw new UnauthorizedException("Not authorized to generate request in this realm", e);

        } catch (EAuthzUnknownRealm e) {

            audit(SecurityDataArchivalRequestEvent.createFailureEvent(
                    getRequestor(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));
            throw new BadRequestException("Invalid realm", e);

        } catch (EBaseException | URISyntaxException e) {

            audit(SecurityDataArchivalRequestEvent.createFailureEvent(
                    getRequestor(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));

            throw new PKIException(e.toString(), e);
        }
    }

    public Response recoverKey(KeyRecoveryRequest data) {
        // auth and authz

        //Check for entirely illegal data combination here
        //Catch this before the internal server processing has to deal with it
        //If data has been provided, we need at least the wrapped session key,
        //or the command is invalid.

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            response = (data.getCertificate() != null)?
                    dao.submitAsyncKeyRecoveryRequest(data, uriInfo, getRequestor(), getAuthToken()):
                    dao.submitRequest(data, uriInfo, getRequestor(), getAuthToken());
            auditRecoveryRequestMade(response.getRequestInfo().getRequestId(),
                    ILogger.SUCCESS, data.getKeyId());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));

        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditRecoveryRequestMade(null, ILogger.FAILURE, data.getKeyId());
            throw new PKIException(e.toString(), e);
        }
    }

    @Override
    public Response approveRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        KeyRequestDAO dao = new KeyRequestDAO();
        if (getRequestor() == null) {
            throw new UnauthorizedException("Request approval must be initiated by an agent");
        }
        try {
            dao.approveRequest(id, getRequestor(), getAuthToken());
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "approve");
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to approve request", e);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "approve");
            throw new PKIException(e.toString(), e);
        }

        return createNoContentResponse();
    }

    @Override
    public Response rejectRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.rejectRequest(id, getAuthToken());
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "reject");
        }catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to reject request", e);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "reject");
            throw new PKIException(e.toString(), e);
        }

        return createNoContentResponse();
    }

    @Override
    public Response cancelRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.cancelRequest(id, getAuthToken());
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "cancel");
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to cancel request", e);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "cancel");
            throw new PKIException(e.toString(), e);
        }

        return createNoContentResponse();
    }

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @Override
    public Response listRequests(String requestState, String requestType, String clientKeyID,
            RequestId start, Integer pageSize, Integer maxResults, Integer maxTime, String realm) {
        if (realm != null) {
            try {
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests", "list");
            } catch (EAuthzAccessDenied e) {
                throw new UnauthorizedException("Not authorized to list these requests", e);
            } catch (EAuthzUnknownRealm e) {
                throw new BadRequestException("Invalid realm", e);
            } catch (EBaseException e) {
                CMS.debug("listRequests: unable to authorize realm" + e);
                throw new PKIException(e.toString(), e);
            }
        }
        // get ldap filter
        String filter = createSearchFilter(requestState, requestType, clientKeyID, realm);
        CMS.debug("listRequests: filter is " + filter);

        start = start == null ? new RequestId(KeyRequestService.DEFAULT_START) : start;
        pageSize = pageSize == null ? DEFAULT_PAGESIZE : pageSize;
        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfoCollection requests;
        try {
            requests = reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            CMS.debug("listRequests: error in obtaining request results" + e);
            e.printStackTrace();
            throw new PKIException(e.toString(), e);
        }
        return createOKResponse(requests);
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

    public void auditRecoveryRequestChange(RequestId requestId, String status, String operation) {
        audit(new SecurityDataRecoveryStateChangeEvent(
                getRequestor(),
                status,
                requestId,
                operation));
    }

    public void auditRecoveryRequestMade(RequestId requestId, String status, KeyId dataId) {
        audit(new SecurityDataRecoveryEvent(
                getRequestor(),
                status,
                requestId,
                dataId,
                null));
    }

    public void auditSymKeyGenRequestMade(RequestId requestId, String status, String clientKeyID) {
        audit(new SymKeyGenerationEvent(
                getRequestor(),
                status,
                requestId,
                clientKeyID));
    }

    public void auditAsymKeyGenRequestMade(RequestId requestId, String status, String clientKeyID) {
        audit(new AsymKeyGenerationEvent(
                getRequestor(),
                status,
                requestId,
                clientKeyID));
    }

    @Override
    public Response submitRequest(MultivaluedMap<String, String> form) {
        ResourceMessage data = new ResourceMessage(form);
        return submitRequest(data);
    }

    @Override
    public Response submitRequest(ResourceMessage data) {
        Object request = null;
        try {
            Class<?> requestClazz = Class.forName(data.getClassName());
            request = requestClazz.getDeclaredConstructor(ResourceMessage.class).newInstance(data);
        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | InstantiationException
                | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            throw new BadRequestException("Invalid request class." + e, e);
        }

        if (request instanceof KeyArchivalRequest) {
            return archiveKey(new KeyArchivalRequest(data));
        } else if (request instanceof KeyRecoveryRequest) {
            return recoverKey(new KeyRecoveryRequest(data));
        } else if (request instanceof SymKeyGenerationRequest) {
            return generateSymKey(new SymKeyGenerationRequest(data));
        } else if (request instanceof AsymKeyGenerationRequest) {
            return generateAsymKey(new AsymKeyGenerationRequest(data));
        } else {
            throw new BadRequestException("Invalid request class.");
        }
    }

    public Response generateSymKey(SymKeyGenerationRequest data) {
        if (data == null) {
            throw new BadRequestException("Invalid key generation request.");
        }

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            if (getRequestor() == null) {
                throw new UnauthorizedException("Key generation must be performed by an agent");
            }
            String realm = data.getRealm();
            if (realm != null) {
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests.symkey", "execute");
            }

            response = dao.submitRequest(data, uriInfo, getRequestor());
            auditSymKeyGenRequestMade(response.getRequestInfo().getRequestId(), ILogger.SUCCESS,
                    data.getClientKeyId());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));
        } catch (EAuthzAccessDenied e) {
            auditSymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new UnauthorizedException("Not authorized to generate request in this realm", e);
        } catch (EAuthzUnknownRealm e) {
            auditSymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new BadRequestException("Invalid realm", e);
        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditSymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new PKIException(e.toString(), e);
        }
    }

    public Response generateAsymKey(AsymKeyGenerationRequest data) {
        if (data == null) {
            throw new BadRequestException("Invalid key generation request.");
        }

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            if (getRequestor() == null) {
                throw new UnauthorizedException("Key generation must be performed by an agent");
            }
            String realm = data.getRealm();
            if (realm != null) {
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests.asymkey", "execute");
            }

            response = dao.submitRequest(data, uriInfo, getRequestor());
            auditAsymKeyGenRequestMade(response.getRequestInfo().getRequestId(), ILogger.SUCCESS,
                    data.getClientKeyId());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));
        } catch (EAuthzAccessDenied e) {
            auditAsymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new UnauthorizedException("Not authorized to generate request in this realm", e);
        } catch (EAuthzUnknownRealm e) {
            auditAsymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new BadRequestException("Invalid realm", e);
        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditAsymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new PKIException(e.toString(), e);
        }
    }

    private IAuthToken getAuthToken() {
        Principal principal = servletRequest.getUserPrincipal();
        PKIPrincipal pkiprincipal = (PKIPrincipal) principal;
        IAuthToken authToken = pkiprincipal.getAuthToken();
        return authToken;
    }

    private String getRequestor() {
        return servletRequest.getUserPrincipal().getName();
    }
}
