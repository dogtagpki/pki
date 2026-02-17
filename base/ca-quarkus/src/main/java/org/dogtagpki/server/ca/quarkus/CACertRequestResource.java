//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
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

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.rest.v1.ProfileService;
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
import com.netscape.cms.authentication.DirBasedAuthentication;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;

/**
 * JAX-RS resource for CA certificate request operations.
 * Replaces CertRequestServlet.
 *
 * Note: Enrollment processing that requires HttpServletRequest for
 * EnrollmentProcessor/RenewalProcessor is handled through the
 * CAEnrollmentResource which provides the necessary request context.
 */
@Path("v2/certrequests")
public class CACertRequestResource {

    private static final Logger logger = LoggerFactory.getLogger(CACertRequestResource.class);
    private static final int DEFAULT_SIZE = 20;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Path("{requestId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequest(@PathParam("requestId") String requestIdStr) throws Exception {
        RequestId id;
        try {
            id = new RequestId(requestIdStr);
        } catch (NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + requestIdStr);
        }
        CertRequestInfo info = getRequestInfo(id);
        return Response.ok(info.toJSON()).build();
    }

    @GET
    @Path("profiles")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listEnrollmentTemplates(
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {

        ProfileDataInfos infos = listEnrollmentTemplates(Locale.getDefault(), start, size);
        return Response.ok(infos.toJSON()).build();
    }

    @GET
    @Path("profiles/{profileId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getEnrollmentTemplate(@PathParam("profileId") String profileId) throws Exception {
        CertEnrollmentRequest req = getEnrollmentTemplate(profileId, Locale.getDefault());
        return Response.ok(req.toJSON()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response enrollCert(
            String requestData,
            @QueryParam("issuer-id") String caIDString,
            @QueryParam("issuer-dn") String caDNString) throws Exception {

        CertEnrollmentRequest enrollmentRequest = JSONSerializer.fromJSON(requestData, CertEnrollmentRequest.class);
        if (enrollmentRequest == null) {
            throw new BadRequestException("Unable to create enrollment request: Missing input data");
        }

        logger.info("CACertRequestResource: Receiving certificate request");
        if (caIDString != null && caDNString != null) {
            throw new BadRequestException("Cannot provide both issuer ID and issuer DN");
        }

        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority ca = engine.getCA();
        AuthorityID aid = null;

        if (caIDString != null) {
            try {
                aid = new AuthorityID(caIDString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Invalid authority ID: " + caIDString, e);
            }
            ca = engine.getCA(aid);
            if (ca == null) {
                throw new ResourceNotFoundException("CA not found: " + caIDString);
            }
        }

        if (caDNString != null) {
            X500Name adn;
            try {
                adn = new X500Name(caDNString);
            } catch (IOException e) {
                throw new BadRequestException("Invalid DN: " + caDNString, e);
            }
            ca = engine.getCA(adn);
            if (ca == null) {
                throw new ResourceNotFoundException("CA not found: " + caDNString);
            }
            aid = ca.getAuthorityID();
        }

        if (!ca.getAuthorityEnabled()) {
            throw new ConflictingOperationException("CA not enabled: " + aid);
        }

        enrollmentRequest.setRemoteHost("");
        enrollmentRequest.setRemoteAddr("");

        CertRequestInfos infos;
        try {
            infos = submitRequest(aid, enrollmentRequest);
        } catch (EAuthException e) {
            throw new UnauthorizedException("Authentication failed: " + e.getMessage(), e);
        } catch (EAuthzException e) {
            throw new UnauthorizedException("Authorization failed: " + e.getMessage(), e);
        } catch (BadRequestDataException e) {
            throw new BadRequestException("Bad request data: " + e.getMessage(), e);
        } catch (EBaseException e) {
            throw new PKIException("Unable to create enrollment request: " + e.getMessage(), e);
        }
        return Response.ok(infos.toJSON()).build();
    }

    private CertRequestInfos submitRequest(AuthorityID aid, CertEnrollmentRequest data) throws Exception {
        CertRequestInfos ret = new CertRequestInfos();

        AuthCredentials credentials = new AuthCredentials();
        String uid = data.getAttribute(DirBasedAuthentication.CRED_UID);
        if (uid != null) credentials.set(DirBasedAuthentication.CRED_UID, uid);
        String password = data.getAttribute(DirBasedAuthentication.CRED_PWD);
        if (password != null) credentials.set(DirBasedAuthentication.CRED_PWD, password);
        String pin = data.getAttribute(DirBasedAuthentication.CRED_PIN);
        if (pin != null) credentials.set(DirBasedAuthentication.CRED_PIN, pin);

        // Note: Full enrollment processing requires HttpServletRequest context
        // for EnrollmentProcessor/RenewalProcessor. In Quarkus, this needs
        // a servlet bridge or refactored processors. For now, we create the
        // request record for later processing.
        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();

        // Store enrollment data for processing
        logger.info("CACertRequestResource: Processing enrollment request for profile: {}", data.getProfileId());

        // The enrollment processing chain requires servlet context.
        // This will be bridged in a future iteration.
        throw new PKIException("Direct enrollment via Quarkus endpoint requires servlet bridge - use agent endpoints or legacy servlet endpoint");
    }

    private CertRequestInfo getRequestInfo(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Unable to get certificate request info: Missing request ID");
        }

        logger.info("CACertRequestResource: Retrieving certificate request {}", id.toHexString());
        CertRequestInfo info;
        try {
            info = getRequest(id);
        } catch (EBaseException e) {
            throw new PKIException("Unable to get cert request info: " + e.getMessage(), e);
        }
        if (info == null) {
            throw new RequestNotFoundException(id);
        }
        return info;
    }

    private CertRequestInfo getRequest(RequestId id) throws EBaseException {
        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        Request request = requestRepository.readRequest(id);
        if (request == null) {
            return null;
        }
        return CertRequestInfoFactory.create(request);
    }

    public CertEnrollmentRequest getEnrollmentTemplate(String profileId, Locale locale) {
        if (profileId == null) {
            throw new BadRequestException("Unable to get enrollment template: Missing Profile ID");
        }

        CAEngine engine = engineQuarkus.getEngine();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (ps == null) {
            throw new PKIException("Unable to get enrollment template: Profile Service not available");
        }

        Profile profile;
        try {
            profile = ps.getProfile(profileId);
            if (profile == null) {
                throw new BadRequestException("Unable to get enrollment template for " + profileId + ": Profile not found");
            }
        } catch (EBaseException e) {
            throw new PKIException("Unable to get enrollment template for " + profileId + ": " + e.getMessage(), e);
        }

        CertEnrollmentRequest request = new CertEnrollmentRequest();
        request.setProfileId(profileId);
        request.setRenewal(Boolean.parseBoolean(profile.isRenewal()));
        request.setRemoteAddr("");
        request.setRemoteHost("");

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
                throw new PKIException("Unable to add input " + id + " to request template: " + e.getMessage(), e);
            }
        }

        return request;
    }

    private ProfileDataInfos listEnrollmentTemplates(Locale locale, int start, int size) {
        CAEngine engine = engineQuarkus.getEngine();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (ps == null) {
            throw new PKIException("Profile subsystem unavailable.");
        }

        ProfileDataInfos infos = new ProfileDataInfos();
        Enumeration<String> e = ps.getProfileIds();
        if (e == null) return infos;

        List<ProfileDataInfo> results = new ArrayList<>();
        while (e.hasMoreElements()) {
            try {
                String id = e.nextElement();
                ProfileDataInfo info = createProfileDataInfo(id, locale);
                if (info == null || !info.getProfileVisible().booleanValue()) {
                    continue;
                }
                results.add(info);
            } catch (EBaseException ex) {
                logger.warn("CACertRequestResource: {}", ex.getMessage());
            }
        }

        int total = results.size();
        infos.setTotal(total);

        for (int i = start; i < start + size && i < total; i++) {
            infos.addEntry(results.get(i));
        }

        return infos;
    }

    private ProfileDataInfo createProfileDataInfo(String profileId, Locale locale) throws EBaseException {
        CAEngine engine = engineQuarkus.getEngine();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (profileId == null) {
            throw new EBaseException("Error creating ProfileDataInfo.");
        }

        Profile profile = ps.getProfile(profileId);
        if (profile == null) {
            return null;
        }

        ProfileDataInfo ret = new ProfileDataInfo();
        ret.setProfileId(profileId);
        ret.setProfileName(profile.getName(locale));
        ret.setProfileDescription(profile.getDescription(locale));
        ret.setProfileVisible(profile.isVisible());
        ret.setProfileEnable(profile.isEnable());
        ret.setProfileEnableBy(profile.getApprovedBy());

        return ret;
    }
}
