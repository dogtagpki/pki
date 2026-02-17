//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Iterator;
import java.util.Locale;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.HTTPGoneException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ServiceUnavailableException;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.CertReviewResponseFactory;
import com.netscape.cms.servlet.cert.RequestProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource for CA agent certificate request operations.
 * Replaces AgentCertRequestServlet.
 *
 * Provides request listing, review, and state change operations
 * (approve, reject, cancel, update, validate, assign, unassign).
 */
@Path("v2/agent/certrequests")
public class CAAgentCertRequestResource {

    private static final Logger logger = LoggerFactory.getLogger(CAAgentCertRequestResource.class);
    private static final int DEFAULT_SIZE = 20;
    private static final int DEFAULT_MAXTIME = 10;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity identity;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listRequests(
            @QueryParam("requestState") String requestState,
            @QueryParam("requestType") String requestType,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("pageSize") @DefaultValue("20") int pageSize,
            @QueryParam("maxTime") Integer maxTime) throws Exception {

        logger.info("CAAgentCertRequestResource: Listing cert requests");
        int effectiveMaxTime = maxTime != null ? maxTime : DEFAULT_MAXTIME;

        try {
            CertRequestInfos requests = listRequests(requestState, requestType, start, pageSize, effectiveMaxTime);
            return Response.ok(requests.toJSON()).build();
        } catch (EBaseException e) {
            throw new PKIException("Unable to list cert requests: " + e.getMessage(), e);
        }
    }

    @GET
    @Path("{requestId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response reviewRequest(@PathParam("requestId") String requestIdStr) throws Exception {
        RequestId id;
        try {
            id = new RequestId(requestIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Invalid request ID: " + requestIdStr);
        }

        try {
            CertReviewResponse req = getRequestData(id);
            if (req == null) {
                throw new RequestNotFoundException(id);
            }
            return Response.ok(req.toJSON()).build();
        } catch (Exception e) {
            throw new PKIException("Unable to review cert request: error retrieving the request", e);
        }
    }

    @POST
    @Path("{requestId}/{operation}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response postRequestOperation(
            @PathParam("requestId") String requestIdStr,
            @PathParam("operation") String operation,
            String requestData) throws Exception {

        RequestId id;
        try {
            id = new RequestId(requestIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Invalid request ID: " + requestIdStr);
        }

        logger.info("CAAgentCertRequestResource: operation {} on certificate request {}", operation, id.toHexString());

        CertReviewResponse data = JSONSerializer.fromJSON(requestData, CertReviewResponse.class);

        try {
            changeRequestState(id, data, Locale.getDefault(), operation);
            return Response.noContent().build();

        } catch (ERejectException e) {
            String message = CMS.getUserMessage(Locale.getDefault(), "CMS_PROFILE_REJECTED", e.getMessage());
            throw new BadRequestException(message, e);

        } catch (EDeferException e) {
            String message = CMS.getUserMessage(Locale.getDefault(), "CMS_PROFILE_DEFERRED", e.toString());
            throw new BadRequestException(message, e);

        } catch (BadRequestDataException e) {
            throw new BadRequestException("Bad request data: " + e.getMessage(), e);

        } catch (CANotFoundException e) {
            throw new HTTPGoneException("CA not found: " + e.getMessage(), e);

        } catch (CADisabledException e) {
            throw new ConflictingOperationException("CA disabled: " + e.getMessage(), e);

        } catch (CAMissingCertException | CAMissingKeyException e) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_CERT_NOT_FOUND", e.toString()), e);
            throw new ServiceUnavailableException(e.toString(), e);

        } catch (EPropertyException e) {
            throw new PKIException("Unable to change request state: " + e.getMessage(), e);

        } catch (EProfileException e) {
            String message = CMS.getUserMessage(Locale.getDefault(), "CMS_INTERNAL_ERROR") + ": " + e.getMessage();
            throw new PKIException(message, e);

        } catch (EBaseException e) {
            throw new PKIException("Unable to change request state: " + e.getMessage(), e);

        } catch (RequestNotFoundException e) {
            throw e;
        }
    }

    private CertReviewResponse getRequestData(RequestId id) throws EBaseException {
        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        Request request = requestRepository.readRequest(id);
        if (request == null) {
            return null;
        }

        String profileId = request.getExtDataInString(Request.PROFILE_ID);
        Profile profile = ps.getProfile(profileId);
        CertReviewResponse info = CertReviewResponseFactory.create(request, profile, null, Locale.getDefault());

        logger.info("CAAgentCertRequestResource: - profile: {}", info.getProfileName());
        logger.info("CAAgentCertRequestResource: - type: {}", info.getRequestType());
        logger.info("CAAgentCertRequestResource: - status: {}", info.getRequestStatus());

        return info;
    }

    public CertRequestInfos listRequests(String requestState, String requestType,
            int start, int pageSize, int maxTime) throws EBaseException {

        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        CertRequestInfos reqInfos = new CertRequestInfos();

        String filter = createSearchFilter(requestState, requestType);
        logger.info("CAAgentCertRequestResource: filter: {}", filter);

        Iterator<RequestRecord> reqs = requestRepository.searchRequest(
                filter, maxTime, start, pageSize);

        while (reqs.hasNext()) {
            Request request = reqs.next().toRequest();
            logger.info("CAAgentCertRequestResource: - request: {}", request.getRequestId().toHexString());
            reqInfos.addEntry(CertRequestInfoFactory.create(request));
        }

        int total = requestRepository.getTotalRequestsByFilter(filter);
        reqInfos.setTotal(total);

        return reqInfos;
    }

    private String createSearchFilter(String requestState, String requestType) {
        String filter = "";
        int matches = 0;

        if ((requestState == null) && (requestType == null)) {
            return "(requeststate=*)";
        }
        if (requestState != null) {
            filter += "(requeststate=" + LDAPUtil.escapeFilter(requestState) + ")";
            matches++;
        }
        if (requestType != null) {
            filter += "(requesttype=" + LDAPUtil.escapeFilter(requestType) + ")";
            matches++;
        }
        if (matches > 1) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }

    private void changeRequestState(RequestId id, CertReviewResponse data,
            Locale locale, String op) throws EBaseException {

        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        Request ireq = requestRepository.readRequest(id);
        if (ireq == null) {
            logger.error("Request not found: {}", id);
            throw new RequestNotFoundException(id);
        }

        RequestProcessor processor = new RequestProcessor("caProfileProcess", locale);
        processor.setCMSEngine(engine);
        processor.init();

        // Get AuthToken from SecurityIdentity
        AuthToken authToken = null;
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            authToken = (AuthToken) core.getAuthToken();
        }

        String authMgr = processor.getAuthenticationManager();
        if (authToken == null && authMgr != null) {
            logger.debug("CAAgentCertRequestResource: auth manager {} configured but no auth token available", authMgr);
        }

        logger.debug("CAAgentCertRequestResource: auth token: {}", authToken);

        // Use null for HttpServletRequest since request processing
        // in Quarkus doesn't have a servlet request available
        processor.processRequest(null, authToken, data, ireq, op);
    }
}
