//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2;

import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.CertReviewResponseFactory;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;

@WebServlet(
        name = "caCertRequest-agent",
        urlPatterns = "/v2/agent/certrequests/*")
public class AgentCertRequestServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(AgentCertRequestServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        if(request.getPathInfo() != null) {
            try {
                RequestId id = new RequestId(request.getPathInfo().substring(1));
                CertReviewResponse req = getRequestData(request, id);
                if(req != null) {
                    out.println(req.toJSON());
                }
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
        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
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
            try {
                reqInfos.addEntry(CertRequestInfoFactory.create(request));
            } catch (NoSuchMethodException e) {
                logger.warn("Error in creating certrequestinfo - no such method: " + e.getMessage(), e);
            }
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

}
