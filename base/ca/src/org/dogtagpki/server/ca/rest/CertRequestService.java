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

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
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
import com.netscape.certsrv.ca.CADisabledException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.cert.CertRequestDAO;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.security.x509.X500Name;

/**
 * @author alee
 *
 */
public class CertRequestService extends PKIService implements CertRequestResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    /**
     * Used to retrieve key request info for a specific request
     */
    @Override
    public Response getRequestInfo(RequestId id) {
        if (id == null) {
            CMS.debug("getRequestInfo: id is null");
            throw new BadRequestException("Unable to get request: invalid id");
        }
        CertRequestInfo info;

        CertRequestDAO dao = new CertRequestDAO();
        try {
            info = dao.getRequest(id, uriInfo);
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new PKIException("Error getting Cert request info!");
        }

        if (info == null) {
            throw new RequestNotFoundException(id);
        }

        return createOKResponse(info);
    }

    @Override
    public Response enrollCert(CertEnrollmentRequest data, String aidString, String adnString) {
        if (data == null) {
            CMS.debug("enrollCert: data is null");
            throw new BadRequestException("Unable to create enrollment reequest: Invalid input data");
        }

        if (aidString != null && adnString != null)
            throw new BadRequestException("Cannot provide both issuer-id and issuer-dn");

        AuthorityID aid = null;
        ICertificateAuthority ca = (ICertificateAuthority)
            CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        if (aidString != null) {
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("invalid AuthorityID: " + aidString);
            }
            ca = ca.getCA(aid);
            if (ca == null)
                throw new ResourceNotFoundException("CA not found: " + aidString);
        }
        if (adnString != null) {
            X500Name adn = null;
            try {
                adn = new X500Name(adnString);
            } catch (IOException e) {
                throw new BadRequestException("invalid DN: " + adnString);
            }
            ca = ca.getCA(adn);
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
            CMS.debug("enrollCert: authentication failed: " + e);
            throw new UnauthorizedException(e.toString());
        } catch (EAuthzException e) {
            CMS.debug("enrollCert: authorization failed: " + e);
            throw new UnauthorizedException(e.toString());
        } catch (BadRequestDataException e) {
            CMS.debug("enrollCert: bad request data: " + e);
            throw new BadRequestException(e.toString());
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException(e);
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }

        // this will return an error code of 200, instead of 201
        // because it is possible to create more than one request
        // as a result of this enrollment

        return createOKResponse(infos);
    }

    @Override
    public Response approveRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "approve");
        return createNoContentResponse();
    }

    @Override
    public Response rejectRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "reject");
        return createNoContentResponse();
    }

    @Override
    public Response cancelRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "cancel");
        return createNoContentResponse();
    }

    @Override
    public Response updateRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "update");
        return createNoContentResponse();
    }

    @Override
    public Response validateRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "validate");
        return createNoContentResponse();
    }

    @Override
    public Response unassignRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "unassign");
        return createNoContentResponse();
    }

    @Override
    public Response assignRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "assign");
        return createNoContentResponse();
    }

    public void changeRequestState(RequestId id, CertReviewResponse data, String op) {
        if (id == null) {
            throw new BadRequestException("Bad data input in CertRequestResourceService. op:" + op);
        }
        CertRequestDAO dao = new CertRequestDAO();
        try {
            dao.changeRequestState(id, servletRequest, data, getLocale(headers), op);
        } catch (ERejectException e) {
            CMS.debug("changeRequestState: execution rejected " + e);
            throw new BadRequestException(CMS.getUserMessage(getLocale(headers), "CMS_PROFILE_REJECTED", e.toString()));
        } catch (EDeferException e) {
            CMS.debug("changeRequestState: execution defered " + e);
            // TODO do we throw an exception here?
            throw new BadRequestException(CMS.getUserMessage(getLocale(headers), "CMS_PROFILE_DEFERRED", e.toString()));
        } catch (BadRequestDataException e) {
            CMS.debug("changeRequestState: bad request data: " + e);
            throw new BadRequestException(e.toString());
        } catch (CADisabledException e) {
            CMS.debug("changeRequestState: CA disabled: " + e);
            throw new ConflictingOperationException(e.toString());
        } catch (EPropertyException e) {
            CMS.debug("changeRequestState: execution error " + e);
            throw new PKIException(CMS.getUserMessage(getLocale(headers),
                    "CMS_PROFILE_PROPERTY_ERROR", e.toString()));
        } catch (EProfileException e) {
            CMS.debug("ProfileProcessServlet: execution error " + e);
            throw new PKIException(CMS.getUserMessage(getLocale(headers), "CMS_INTERNAL_ERROR"));
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Problem approving request in CertRequestResource.assignRequest! " + e);
        } catch (RequestNotFoundException e) {
            CMS.debug(e);
            throw e;
        }
    }

    @Override
    public Response reviewRequest(@PathParam("id") RequestId id) {
        if (id == null) {
            CMS.debug("reviewRequest: id is null");
            throw new BadRequestException("Unable to review request: invalid id");
        }
        CertReviewResponse info;

        CertRequestDAO dao = new CertRequestDAO();
        try {
            info = dao.reviewRequest(servletRequest, id, uriInfo, getLocale(headers));
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new PKIException("Error getting Cert request info!");
        }

        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
        }

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
        CMS.debug("listRequests: filter is " + filter);

        start = start == null ? new RequestId(CertRequestService.DEFAULT_START) : start;
        pageSize = pageSize == null ? DEFAULT_PAGESIZE : pageSize;
        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        CertRequestDAO reqDAO = new CertRequestDAO();
        CertRequestInfos requests;
        try {
            requests =  reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            CMS.debug("listRequests: error in obtaining request results" + e);
            e.printStackTrace();
            throw new PKIException("Error listing cert requests!");
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
            CMS.debug("getEnrollmenTemplate: invalid request. profileId is null");
            throw new BadRequestException("Invalid ProfileId");
        }

        IProfileSubsystem ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);
        if (ps == null) {
            CMS.debug("getEnrollmentTemplate: ps is null");
            throw new PKIException("Error modifying profile state.  Profile Service not available");
        }

        IProfile profile = null;
        try {
            profile = ps.getProfile(profileId);
            if (profile == null) {
                throw new BadRequestException("Cannot provide enrollment template for profile `" + profileId +
                        "`.  Profile not found");
            }
        } catch (EBaseException e) {
            CMS.debug("getEnrollmentTemplate(): error obtaining profile `" + profileId + "`: " + e);
            e.printStackTrace();
            throw new PKIException("Error generating enrollment template.  Cannot obtain profile.");
        }

        if (! profile.isVisible()) {
            CMS.debug("getEnrollmentTemplate(): attempt to get enrollment template for non-visible profile. This is ok since command line enrollments should be able to use enabled but non visible profiles.");

        }

        CertEnrollmentRequest request = new CertEnrollmentRequest();
        request.setProfileId(profileId);
        request.setRenewal(Boolean.parseBoolean(profile.isRenewal()));
        request.setRemoteAddr("");
        request.setRemoteHost("");
        request.setSerialNum("");

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
                CMS.debug("getEnrollmentTemplate(): Failed to add input " + id + " to request template: " + e);
                e.printStackTrace();
                throw new PKIException("Failed to add input" + id + "to request template");
            }
        }

        return createOKResponse(request);
    }

    @Override
    public Response listEnrollmentTemplates(Integer start, Integer size) {

        start = start == null ? DEFAULT_START : start;
        size = size == null ? DEFAULT_PAGESIZE : size;

        IProfileSubsystem ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);

        if (ps == null) {
            throw new PKIException("Profile subsystem unavailable.");
        }

        ProfileDataInfos infos = new ProfileDataInfos();
        boolean visibleOnly = true;

        Enumeration<String> e = ps.getProfileIds();
        if (e == null) return createOKResponse(infos);

        // store non-null results in a list
        List<ProfileDataInfo> results = new ArrayList<ProfileDataInfo>();
        while (e.hasMoreElements()) {
            try {
                String id = e.nextElement();
                ProfileDataInfo info = ProfileService.createProfileDataInfo(id, visibleOnly, uriInfo, getLocale(headers));
                if (info == null) continue;
                results.add(info);
            } catch (EBaseException ex) {
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
