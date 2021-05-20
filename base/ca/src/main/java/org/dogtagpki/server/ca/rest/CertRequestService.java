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

package org.dogtagpki.server.ca.rest;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.HTTPGoneException;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.ServiceUnavailableException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.CAMissingCertException;
import com.netscape.certsrv.ca.CAMissingKeyException;
import com.netscape.certsrv.ca.CANotFoundException;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class CertRequestService extends PKIService implements CertRequestResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRequestService.class);

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    /**
     * Used to retrieve key request info for a specific request
     */
    @Override
    public Response getRequestInfo(RequestId id) {

        logger.info("CertRequestService: Retrieving certificate request " + id);

        if (id == null) {
            String message = "Unable to get certificate request info: Missing request ID";
            logger.error(message);
            throw new BadRequestException(message);
        }
        CertRequestInfo info;

        CertRequestDAO dao = new CertRequestDAO();
        try {
            info = dao.getRequest(id, uriInfo);
        } catch (EBaseException e) {
            String message = "Unable to get cert request info: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        if (info == null) {
            throw new RequestNotFoundException(id);
        }

        return createOKResponse(info);
    }

    @Override
    public Response enrollCert(CertEnrollmentRequest data, String aidString, String adnString) {

        logger.info("CertRequestService: Receiving certificate request");

        if (data == null) {
            String message = "Unable to create enrollment request: Missing input data";
            logger.error(message);
            throw new BadRequestException(message);
        }

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

        CertRequestDAO dao = new CertRequestDAO();

        CertRequestInfos infos;
        try {
            infos = dao.submitRequest(aid, data, servletRequest, uriInfo, getLocale(headers));

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

        // this will return an error code of 200, instead of 201
        // because it is possible to create more than one request
        // as a result of this enrollment

        return createOKResponse(infos);
    }

    @Override
    public Response approveRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Approving certificate request " + id);

        changeRequestState(id, data, "approve");
        return createNoContentResponse();
    }

    @Override
    public Response rejectRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Rejecting certificate request " + id);

        changeRequestState(id, data, "reject");
        return createNoContentResponse();
    }

    @Override
    public Response cancelRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Canceling certificate request " + id);

        changeRequestState(id, data, "cancel");
        return createNoContentResponse();
    }

    @Override
    public Response updateRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Updating certificate request " + id);

        changeRequestState(id, data, "update");
        return createNoContentResponse();
    }

    @Override
    public Response validateRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Validating certificate request " + id);

        changeRequestState(id, data, "validate");
        return createNoContentResponse();
    }

    @Override
    public Response unassignRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Unassigning certificate request " + id);

        changeRequestState(id, data, "unassign");
        return createNoContentResponse();
    }

    @Override
    public Response assignRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Assigning certificate request " + id);

        changeRequestState(id, data, "assign");
        return createNoContentResponse();
    }

    public void changeRequestState(RequestId id, CertReviewResponse data, String op) {

        if (id == null) {
            throw new BadRequestException("Unable to change request state: Missing input data");
        }

        CertRequestDAO dao = new CertRequestDAO();

        try {
            dao.changeRequestState(id, servletRequest, data, getLocale(headers), op);

        } catch (ERejectException e) {
            String message = CMS.getUserMessage(getLocale(headers), "CMS_PROFILE_REJECTED", e.getMessage());
            logger.error(message, e);
            throw new BadRequestException(message, e);

        } catch (EDeferException e) {
            String message = CMS.getUserMessage(getLocale(headers), "CMS_PROFILE_DEFERRED", e.toString());
            logger.error(message, e);
            // TODO do we throw an exception here?
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
            throw new ServiceUnavailableException(e.toString(), e);

        } catch (EPropertyException e) {
            String message = CMS.getUserMessage(getLocale(headers),
                    "CMS_PROFILE_PROPERTY_ERROR", e.getMessage());
            logger.error(message, e);
            throw new PKIException(message, e);

        } catch (EProfileException e) {
            String message = CMS.getUserMessage(getLocale(headers), "CMS_INTERNAL_ERROR") + ": " + e.getMessage();
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
    }

    @Override
    public Response reviewRequest(@PathParam("id") RequestId id) {

        logger.info("CertRequestService: Reviewing certificate request " + id);

        if (id == null) {
            String message = "Unable to review cert request: Missing request ID";
            logger.error(message);
            throw new BadRequestException(message);
        }
        CertReviewResponse info;

        CertRequestDAO dao = new CertRequestDAO();
        try {
            info = dao.reviewRequest(servletRequest, id, uriInfo, getLocale(headers));
        } catch (EBaseException e) {
            String message = "Unable to review cert request: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
        }

        logger.info("CertRequestService:   Profile: " + info.getProfileName());
        logger.info("CertRequestService:   Type: " + info.getRequestType());
        logger.info("CertRequestService:   Status: " + info.getRequestStatus());

        return createOKResponse(info);
    }

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    @Override
    public Response listRequests(String requestState, String requestType,
            RequestId start, Integer pageSize, Integer maxResults, Integer maxTime) {
        // get ldap filter
        String filter = createSearchFilter(requestState, requestType);
        logger.debug("listRequests: filter is " + filter);

        start = start == null ? new RequestId(CertRequestService.DEFAULT_START) : start;
        pageSize = pageSize == null ? DEFAULT_PAGESIZE : pageSize;
        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        CertRequestDAO reqDAO = new CertRequestDAO();
        CertRequestInfos requests;
        try {
            requests =  reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            String message = "Unable to list cert requests: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        return createOKResponse(requests);
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

    @Override
    public Response getEnrollmentTemplate(String profileId) {
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
                ProfileInput input = ProfileService.createProfileInput(profile, id, getLocale(headers));
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

        return createOKResponse(request);
    }

    @Override
    public Response listEnrollmentTemplates(Integer start, Integer size) {

        start = start == null ? DEFAULT_START : start;
        size = size == null ? DEFAULT_PAGESIZE : size;

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        if (ps == null) {
            throw new PKIException("Profile subsystem unavailable.");
        }

        ProfileDataInfos infos = new ProfileDataInfos();
        boolean visibleOnly = true;

        Enumeration<String> e = ps.getProfileIds();
        if (e == null) return createOKResponse(infos);

        // store non-null results in a list
        List<ProfileDataInfo> results = new ArrayList<>();
        while (e.hasMoreElements()) {
            try {
                String id = e.nextElement();
                ProfileDataInfo info = ProfileService.createProfileDataInfo(id, visibleOnly, uriInfo, getLocale(headers));
                if (info == null) continue;
                results.add(info);
            } catch (EBaseException ex) {
                logger.warn("CertRequestService: " + ex.getMessage());
                continue;
            }
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

        return createOKResponse(infos);
    }
}
