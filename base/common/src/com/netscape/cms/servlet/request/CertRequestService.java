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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UnauthorizedException;
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
import com.netscape.cms.servlet.profile.ProfileService;
import com.netscape.cmsutil.ldap.LDAPUtil;

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
    public CertRequestInfo getRequestInfo(RequestId id) {
        // auth and authz
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
            // request does not exist
            throw new RequestNotFoundException(id);
        }

        return info;
    }

    // Enrollment - used to test integration with a browser
    public CertRequestInfos enrollCert(MultivaluedMap<String, String> form) {
        CertEnrollmentRequest data = new CertEnrollmentRequest(form);
        return enrollCert(data);
    }

    public CertRequestInfos enrollCert(CertEnrollmentRequest data) {
        CertRequestInfos infos;
        if (data == null) {
            throw new BadRequestException("Bad data input into CertRequestResourceService.enrollCert!");
        }
        CertRequestDAO dao = new CertRequestDAO();

        try {
            infos = dao.submitRequest(data, servletRequest, uriInfo, getLocale(headers));
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
            throw new PKIException(e.toString());
        }

        return infos;
    }

    public void approveRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "approve");
    }

    public void rejectRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "reject");
    }

    public void cancelRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "cancel");
    }

    public void updateRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "update");
    }

    public void validateRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "validate");
    }

    public void unassignRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "unassign");
    }

    public void assignRequest(RequestId id, CertReviewResponse data) {
        changeRequestState(id, data, "assign");
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
            throw new BadRequestException(CMS.getUserMessage(getLocale(headers), "CMS_REQUEST_NOT_FOUND", id.toString()));
        }
    }

    public CertReviewResponse reviewRequest(@PathParam("id") RequestId id) {
     // auth and authz
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

        return info;
    }

    /**
     * Used to generate list of cert requests based on the search parameters
     */
    public CertRequestInfos listRequests(String requestState, String requestType,
            RequestId start, Integer pageSize, Integer maxResults, Integer maxTime) {
        // auth and authz

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
        return requests;
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
    public CertEnrollmentRequest getEnrollmentTemplate(String profileId) {
        IProfileSubsystem ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);
        if (ps == null) {
            CMS.debug("getEnrollmentTemplate: ps is null");
            throw new PKIException("Error modifying profile state.  Profile Service not available");
        }

        if (profileId == null) {
            CMS.debug("getEnrollmenTemplate: invalid request. profileId is null");
            throw new BadRequestException("Invalid ProfileId");
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
            CMS.debug("getEnrollmentTemplate(): attempt to get enrollment template for non-visible profile");
            throw new BadRequestException("Cannot provide enrollment template for profile `" + profileId +
                        "`.  Profile not marked as visible");
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
                for (ProfileAttribute attr: input.getAttrs()) {
                    attr.setValue("");
                }
                request.addInput(input);
            } catch (EBaseException e) {
                CMS.debug("getEnrollmentTemplate(): Failed to add input " + id + " to request template: " + e);
                e.printStackTrace();
                throw new PKIException("Failed to add input" + id + "to request template");
            }
        }

        return request;
    }

    @Override
    public ProfileDataInfos listEnrollmentTemplates() {
        IProfileSubsystem ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);
        List<ProfileDataInfo> list = new ArrayList<ProfileDataInfo>();
        ProfileDataInfos infos = new ProfileDataInfos();
        boolean visibleOnly = true;

        if (ps == null) {
            return null;
        }

        Enumeration<String> profileIds = ps.getProfileIds();
        if (profileIds != null) {
            while (profileIds.hasMoreElements()) {
                String id = profileIds.nextElement();
                ProfileDataInfo info = null;
                try {
                    info = ProfileService.createProfileDataInfo(id, visibleOnly, uriInfo, getLocale(headers));
                } catch (EBaseException e) {
                    continue;
                }

                if (info != null) {
                    list.add(info);
                }
            }
        }

        infos.setProfileInfos(list);
        return infos;
    }

}
