//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.rest.ProfileService;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.cert.RenewalProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;
/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caCertRequest",
        urlPatterns = "/v2/certrequests/*")
public class CertRequestServlet extends CAServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(CertRequestServlet.class);

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("CertRequestServlet.get(): session: {}", session.getId());

        PrintWriter out = response.getWriter();
        if(request.getPathInfo() == null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }

        String[] pathElement = request.getPathInfo().substring(1).split("/");
        if (pathElement.length == 1) {
            if (pathElement[0].equals("profiles")) {
                int size = request.getParameter("size") == null ?
                        DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
                int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
                ProfileDataInfos infos = listEnrollmentTemplates(request, start, size);
                out.println(infos.toJSON());
                return;
            }
            RequestId id;
            try {
                id = new RequestId(pathElement[0]);
            } catch(NumberFormatException e) {
                throw new BadRequestException("Id not valid: " + pathElement[0]);
            }
            CertRequestInfo info = getRequestInfo(id);
            out.println(info.toJSON());
            return;
        }
        if (pathElement.length == 2 && pathElement[0].equals("profiles")) {
            CertEnrollmentRequest req = getEnrollmentTemplate(pathElement[1], request.getLocale());
            out.println(req.toJSON());
            return;
        }
        response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());


    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("CertServlet.post(): session: {}", session.getId());

        if(request.getPathInfo() != null) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, request.getRequestURI());
            return;
        }

        BufferedReader reader = request.getReader();
        String postMessage = reader.lines().collect(Collectors.joining());

        CertEnrollmentRequest enrollmentRequest = JSONSerializer.fromJSON(postMessage, CertEnrollmentRequest.class);
        if (enrollmentRequest == null) {
            String message = "Unable to create enrollment request: Missing input data";
            logger.error(message);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
        }
        String caIDString = request.getParameter("issuer-id");
        String caDNString = request.getParameter("issuer-dn");

        CertRequestInfos infos = enrollCert(request, enrollmentRequest, caIDString, caDNString);

        PrintWriter out = response.getWriter();
        out.println(infos.toJSON());
    }

    private CertRequestInfos enrollCert(HttpServletRequest servletRequest, CertEnrollmentRequest data, String aidString, String adnString) {

        logger.info("CertRequestServlet: Receiving certificate request");
        if (aidString != null && adnString != null)
            throw new BadRequestException("Cannot provide both issuer-id and issuer-dn");

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        AuthorityID aid = null;
        if (aidString != null) {
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("invalid AuthorityID: " + aidString, e);
            }

            ca = engine.getCA(aid);

            if (ca == null)
                throw new ResourceNotFoundException("CA not found: " + aidString);
        }

        if (adnString != null) {
            X500Name adn = null;
            try {
                adn = new X500Name(adnString);
            } catch (IOException e) {
                throw new BadRequestException("invalid DN: " + adnString, e);
            }

            ca = engine.getCA(adn);

            if (ca == null)
                throw new ResourceNotFoundException("CA not found: " + adnString);

            aid = ca.getAuthorityID();
        }

        if (!ca.getAuthorityEnabled())
            throw new ConflictingOperationException("CA not enabled: " + aid.toString());

        data.setRemoteHost(servletRequest.getRemoteHost());
        data.setRemoteAddr(servletRequest.getRemoteAddr());

        CertRequestInfos infos;
        try {
            infos = submitRequest(aid, data, servletRequest);

        } catch (EAuthException e) {
            String message = "Authentication failed: " + e.getMessage();
            logger.error(message, e);
            throw new UnauthorizedException(message, e);

        } catch (EAuthzException e) {
            String message = "Authorization failed: " + e.getMessage();
            logger.error(message, e);
            throw new UnauthorizedException(message, e);

        } catch (BadRequestDataException e) {
            String message = "Bad request data: " + e.getMessage();
            logger.error(message, e);
            throw new BadRequestException(message, e);

        } catch (EBaseException e) {
            String message = "Unable to create enrollment request: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);

        } catch (Exception e) {
            String message = "Unable to create enrollment request: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        return infos;
    }


    /**
     * Submits an enrollment request and processes it.
     *
     * @param data
     * @return info for the request submitted.
     * @throws Exception
     */
    private CertRequestInfos submitRequest(
            AuthorityID aid,
            CertEnrollmentRequest data,
            HttpServletRequest request)
        throws Exception {

        CertRequestInfos ret = new CertRequestInfos();

        AuthCredentials credentials = new AuthCredentials();
        String uid = data.getAttribute("uid");
        if (uid != null) {
            credentials.set("uid", uid);
        }
        String password = data.getAttribute("pwd");
        if (password != null) {
            credentials.set("pwd", password);
        }

        CAEngine engine = CAEngine.getInstance();

        HashMap<String, Object> results = null;
        if (data.isRenewal()) {
            RenewalProcessor processor = new RenewalProcessor("caProfileSubmit", request.getLocale());
            processor.setCMSEngine(engine);
            processor.init();

            results = processor.processRenewal(data, request, credentials);

        } else {
            EnrollmentProcessor processor = new EnrollmentProcessor("caProfileSubmit", request.getLocale());
            processor.setCMSEngine(engine);
            processor.init();

            results = processor.processEnrollment(data, request, aid, credentials);
        }

        Request[] reqs = (Request[]) results.get(CAProcessor.ARG_REQUESTS);
        for (Request req : reqs) {
            CertRequestInfo info = CertRequestInfoFactory.create(req);
            ret.addEntry(info);
        }

        ret.setTotal(ret.getEntries().size());

        // TODO - what happens if the errorCode is internal error ?

        return ret;
    }

    private ProfileDataInfos listEnrollmentTemplates(HttpServletRequest request, Integer start, Integer size) {

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (ps == null) {
            throw new PKIException("Profile subsystem unavailable.");
        }

        ProfileDataInfos infos = new ProfileDataInfos();

        Enumeration<String> e = ps.getProfileIds();
        if (e == null) return infos;

        // store non-null results in a list
        List<ProfileDataInfo> results = new ArrayList<>();
        while (e.hasMoreElements()) {
            try {
                String id = e.nextElement();
                ProfileDataInfo info = createProfileDataInfo(id, request.getLocale());
                if (info == null || !info.getProfileVisible().booleanValue()) {
                    continue;
                }
                results.add(info);
            } catch (EBaseException ex) {
                logger.warn("CertRequestServlet: {}",  ex.getMessage());
            }
        }

        int total = results.size();
        infos.setTotal(total);

        // return entries in the requested page
        for (int i = start; i < start + size && i < total; i++) {
            infos.addEntry(results.get(i));
        }

        return infos;
    }

    private CertRequestInfo getRequestInfo(RequestId id) {

        if (id == null) {
            String message = "Unable to get certificate request info: Missing request ID";
            logger.error(message);
            throw new BadRequestException(message);
        }

        logger.info("CertRequestServlet: Retrieving certificate request " + id.toHexString());
        CertRequestInfo info;
        try {
            info = getRequest(id);
        } catch (EBaseException e) {
            String message = "Unable to get cert request info: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        if (info == null) {
            throw new RequestNotFoundException(id);
        }
        return info;
    }

    public CertEnrollmentRequest getEnrollmentTemplate(String profileId, Locale locale) {
        if (profileId == null) {
            String message = "Unable to get enrollment template: Missing Profile ID";
            logger.error(message);
            throw new BadRequestException(message);
        }

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (ps == null) {
            String message = "Unable to get enrollment template: Profile Service not available";
            logger.error(message);
            throw new PKIException(message);
        }

        Profile profile = null;
        try {
            profile = ps.getProfile(profileId);
            if (profile == null) {
                String message = "Unable to get enrollment template for " + profileId + ": Profile not found";
                logger.error(message);
                throw new BadRequestException(message);
            }

        } catch (EBaseException e) {
            String message = "Unable to get enrollment template for " + profileId + ": " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        if (! profile.isVisible()) {
            logger.debug("getEnrollmentTemplate(): getting enrollment template for non-visible profile.");
            // This is ok since command line enrollments should be able to use enabled but non visible profiles.
        }

        CertEnrollmentRequest request = new CertEnrollmentRequest();
        request.setProfileId(profileId);
        request.setRenewal(Boolean.parseBoolean(profile.isRenewal()));
        request.setRemoteAddr("");
        request.setRemoteHost("");

        // populate inputs
        Enumeration<String> inputIds = profile.getProfileInputIds();
        while (inputIds.hasMoreElements()) {
            String id = inputIds.nextElement();
            try {
                ProfileInput input = ProfileService.createProfileInput(profile, id, locale);
                for (ProfileAttribute attr : input.getAttributes()) {
                    attr.setValue("");
                }
                request.addInput(input);
            } catch (EBaseException e) {
                String message = "Unable to add input " + id + " to request template: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }
        }

        return request;
    }

    private ProfileDataInfo createProfileDataInfo(String profileId, Locale locale) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (profileId == null) {
            throw new EBaseException("Error creating ProfileDataInfo.");
        }
        ProfileDataInfo ret = null;

        Profile profile = null;

        profile = ps.getProfile(profileId);
        if (profile == null) {
            return null;
        }

        ret = new ProfileDataInfo();

        ret.setProfileId(profileId);
        ret.setProfileName(profile.getName(locale));
        ret.setProfileDescription(profile.getDescription(locale));

        ret.setProfileVisible(profile.isVisible());
        ret.setProfileEnable(profile.isEnable());
        ret.setProfileEnableBy(profile.getApprovedBy());

        return ret;
    }

    /**
     * Gets info for a specific request
     *
     * @param id
     * @return info for specific request
     * @throws EBaseException
     */
    private CertRequestInfo getRequest(RequestId id) throws EBaseException {
        CAEngine engine = CAEngine.getInstance();
        RequestRepository requestRepository = engine.getRequestRepository();

        Request request = requestRepository.readRequest(id);
        if (request == null) {
            return null;
        }
        return CertRequestInfoFactory.create(request);
    }

}
