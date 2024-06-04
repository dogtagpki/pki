//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.CertReviewResponseFactory;
import com.netscape.cms.servlet.cert.RequestProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caCertRequest-agent",
        urlPatterns = "/v2/agent/certrequests/*")
public class AgentCertRequestServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(AgentCertRequestServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        PrintWriter out = response.getWriter();
        if(request.getPathInfo() != null) {
            RequestId id;
            try {
                id = new RequestId(request.getPathInfo().substring(1));
            } catch(NumberFormatException e) {
                throw new BadRequestException("Id not valid: " + request.getPathInfo().substring(1));
            }
            try {
                CertReviewResponse req = getRequestData(request, id);
                if(req == null) {
                    throw new RequestNotFoundException(id);
                }
                out.println(req.toJSON());
            } catch (Exception e) {
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            }
            return;
        }
        int maxTime = request.getParameter("maxTime") == null ?
                DEFAULT_MAXTIME : Integer.parseInt(request.getParameter("maxTime"));
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String requestType = request.getParameter("requestType");
        String requestState = request.getParameter("requestState");
        CertRequestInfos requests = null;
        try {
            requests =  listRequests(requestState, requestType, start, size, maxTime);
            out.println(requests.toJSON());
        } catch (EBaseException e) {
            String message = "Unable to list cert requests: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AgentCertRequestServlet.post(): session: {}", session.getId());

        if (request.getPathInfo() == null || request.getPathInfo().isEmpty()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");

        if (pathElement.length != 2) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }

        RequestId id;
        try {
            id = new RequestId(pathElement[0]);
        } catch(NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + pathElement[0]);
        }

        if (pathElement[1].matches("approve|reject|cancel|update|validate|unassign|assign")) {
            logger.info("AgentCertRequestServlet: operation {} on certificate request {}",pathElement[1], id.toHexString());
            BufferedReader reader = request.getReader();
            String postMessage = reader.lines().collect(Collectors.joining());

            CertReviewResponse data = JSONSerializer.fromJSON(postMessage, CertReviewResponse.class);

            try {
                changeRequestState(id, request, data, request.getLocale(), pathElement[1]);

            } catch (ERejectException e) {
                String message = CMS.getUserMessage(request.getLocale(), "CMS_PROFILE_REJECTED", e.getMessage());
                logger.error(message, e);
                throw new BadRequestException(message, e);

            } catch (EDeferException e) {
                String message = CMS.getUserMessage(request.getLocale(), "CMS_PROFILE_DEFERRED", e.toString());
                logger.error(message, e);
                throw new BadRequestException(message, e);

            } catch (BadRequestDataException e) {
                String message = "Bad request data: " + e.getMessage();
                logger.error(message, e);
                throw new BadRequestException(message, e);

            } catch (CANotFoundException e) {
                // The target CA does not exist (deleted between
                // request submission and approval).
                String message = "CA not found: " + e.getMessage();
                logger.error(message, e);
                throw new HTTPGoneException(message, e);

            } catch (CADisabledException e) {
                String message = "CA disabled: " + e.getMessage();
                logger.error(message, e);
                throw new ConflictingOperationException(message, e);

            } catch (CAMissingCertException | CAMissingKeyException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_SIGNING_CERT_NOT_FOUND", e.toString()), e);
                throw new ServiceUnavailableException(e.toString(), e);

            } catch (EPropertyException e) {
                logger.error("AgentCertRequestServlet: Unable to change request state: " + e.getMessage(), e);
                throw new PKIException("Unable to change request state: " + e.getMessage(), e);

            } catch (EProfileException e) {
                String message = CMS.getUserMessage(request.getLocale(), "CMS_INTERNAL_ERROR") + ": " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);

            } catch (EBaseException e) {
                String message = "Unable to change request state: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);

            } catch (RequestNotFoundException e) {
                String message = "Unable to change request state: " + e.getMessage();
                logger.error(message, e);
                throw e;
            }

        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
        }
    }

    private CertReviewResponse getRequestData(HttpServletRequest servletRequest, RequestId id) throws EBaseException {
        CertReviewResponse info = null;
        CAEngine engine = getCAEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        ProfileSubsystem ps = engine.getProfileSubsystem();
        SecureRandom random = null;
        if (engine.getEnableNonces()) {
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            random = jssSubsystem.getRandomNumberGenerator();
        }


        Request request = requestRepository.readRequest(id);

        if (request == null) {
            return null;
        }

        String profileId = request.getExtDataInString(Request.PROFILE_ID);

        Profile profile = ps.getProfile(profileId);
        info = CertReviewResponseFactory.create(request, profile, null, servletRequest.getLocale());

        if (random != null) {
            // generate nonce
            long n = random.nextLong();
            logger.info("AgentCertRequestServlet: Nonce: {}", n);

            // store nonce in session
            Map<Object, Long> nonces = engine.getNonces(servletRequest, "cert-request");
            nonces.put(info.getRequestId().toBigInteger(), n);

            // return nonce to client
            info.setNonce(Long.toString(n));
        }
        logger.info("AgentCertRequestServlet: - profile: {}", info.getProfileName());
        logger.info("AgentCertRequestServlet: - type: {}", info.getRequestType());
        logger.info("AgentCertRequestServlet: - status: {}", info.getRequestStatus());

        return info;
    }

    public CertRequestInfos listRequests(String requestState, String requestType,
            int start, int pageSize, int maxTime) throws EBaseException {
        logger.info("AgentCertRequestServlet: performing requests search");

        CAEngine engine = getCAEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        CertRequestInfos reqInfos = new CertRequestInfos();

        String filter = createSearchFilter(requestState, requestType);
        logger.debug("AgentCertRequestServlet: performing paged search");

        Iterator<RequestRecord> reqs = requestRepository.searchRequest(
                filter,
                maxTime,
                start,
                pageSize + 1);

        while(reqs.hasNext()) {
            Request request = reqs.next().toRequest();
            logger.debug("- {}", request.getRequestId().toHexString());
            reqInfos.addEntry(CertRequestInfoFactory.create(request));
        }
        reqInfos.setTotal(requestRepository.getTotalRequestsByFilter(filter));

        // builder for search links
        return reqInfos;
    }

    private String createSearchFilter(String requestState, String requestType) {
        String filter = "";
        int matches = 0;

        if ((requestState == null) && (requestType == null)) {
            filter = "(requeststate=*)";
            return filter;
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

    private void changeRequestState(RequestId id, HttpServletRequest request, CertReviewResponse data,
            Locale locale, String op) throws EBaseException {
        CAEngine engine = getCAEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        Request ireq = requestRepository.readRequest(id);
        if (ireq == null) {
            throw new RequestNotFoundException(id);
        }

        RequestProcessor processor = new RequestProcessor("caProfileProcess", locale);
        processor.setCMSEngine(engine);
        processor.init();

        AuthToken authToken = null;

        Principal principal = request.getUserPrincipal();
        if (principal instanceof PKIPrincipal pkiPrincipal) {
            logger.debug("AgentCertRequestServlet: getting auth token from user principal");
            authToken = pkiPrincipal.getAuthToken();
        }

        String authMgr = processor.getAuthenticationManager();
        if (authToken == null && authMgr != null) {
            logger.debug("AgentCertRequestServlet: getting auth token from {}", authMgr);
            authToken = processor.authenticate(request);
        }

        logger.debug("AgentCertRequestServlet: auth token: {}", authToken);

        processor.processRequest(request, authToken, data, ireq, op);
    }
}
