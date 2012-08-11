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

import javax.ws.rs.PathParam;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.BadRequestException;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.request.model.AgentEnrollmentRequestData;
import com.netscape.cms.servlet.request.model.CertRequestDAO;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRequestInfos;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class CertRequestService extends PKIService implements CertRequestResource {

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
            throw new CMSException("Error getting Cert request info!");
        }

        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
        }

        return info;
    }

    // Enrollment - used to test integration with a browser
    public CertRequestInfos enrollCert(MultivaluedMap<String, String> form) {
        EnrollmentRequestData data = new EnrollmentRequestData(form);
        return enrollCert(data);
    }

    public CertRequestInfos enrollCert(EnrollmentRequestData data) {
        CertRequestInfos infos;
        if (data == null) {
            throw new BadRequestException("Bad data input into CertRequestResourceService.enrollCert!");
        }
        CertRequestDAO dao = new CertRequestDAO();

        try {
            infos = dao.submitRequest(data, servletRequest, uriInfo, getLocale());
        } catch (EAuthException e) {
            CMS.debug("enrollCert: authentication failed: " + e);
            throw new CMSException(Response.Status.UNAUTHORIZED, e.toString());
        } catch (EAuthzException e) {
            CMS.debug("enrollCert: authorization failed: " + e);
            throw new CMSException(Response.Status.UNAUTHORIZED, e.toString());
        } catch (BadRequestDataException e) {
            CMS.debug("enrollCert: bad request data: " + e);
            throw new CMSException(Response.Status.BAD_REQUEST, e.toString());
        } catch (EBaseException e) {
            throw new CMSException(e.toString());
        }

        return infos;
    }

    public void approveRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "approve");
    }

    public void rejectRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "reject");
    }

    public void cancelRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "cancel");
    }

    public void updateRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "update");
    }

    public void validateRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "validate");
    }

    public void unassignRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "unassign");
    }

    public void assignRequest(RequestId id, AgentEnrollmentRequestData data) {
        changeRequestState(id, data, "assign");
    }

    public void changeRequestState(RequestId id, AgentEnrollmentRequestData data, String op) {
        if (id == null) {
            throw new BadRequestException("Bad data input in CertRequestResourceService. op:" + op);
        }
        CertRequestDAO dao = new CertRequestDAO();
        try {
            dao.changeRequestState(id, servletRequest, data, getLocale(), op);
        } catch (ERejectException e) {
            CMS.debug("changeRequestState: execution rejected " + e);
            throw new CMSException(Response.Status.BAD_REQUEST,
                    CMS.getUserMessage(getLocale(), "CMS_PROFILE_REJECTED", e.toString()));
        } catch (EDeferException e) {
            CMS.debug("changeRequestState: execution defered " + e);
            // TODO do we throw an exception here?
            throw new CMSException(Response.Status.BAD_REQUEST,
                    CMS.getUserMessage(getLocale(), "CMS_PROFILE_DEFERRED", e.toString()));
        } catch (BadRequestDataException e) {
            CMS.debug("changeRequestState: bad request data: " + e);
            throw new CMSException(Response.Status.BAD_REQUEST, e.toString());
        } catch (EPropertyException e) {
            CMS.debug("changeRequestState: execution error " + e);
            throw new CMSException(CMS.getUserMessage(getLocale(),
                    "CMS_PROFILE_PROPERTY_ERROR", e.toString()));
        } catch (EProfileException e) {
            CMS.debug("ProfileProcessServlet: execution error " + e);
            throw new CMSException(CMS.getUserMessage(getLocale(), "CMS_INTERNAL_ERROR"));
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new CMSException("Problem approving request in CertRequestResource.assignRequest! " + e);
        } catch (RequestNotFoundException e) {
            CMS.debug(e);
            throw new CMSException(Response.Status.BAD_REQUEST,
                    CMS.getUserMessage(getLocale(), "CMS_REQUEST_NOT_FOUND", id.toString()));
        }
    }

    public AgentEnrollmentRequestData reviewRequest(@PathParam("id") RequestId id) {
     // auth and authz
        AgentEnrollmentRequestData info;

        CertRequestDAO dao = new CertRequestDAO();
        try {
            info = dao.reviewRequest(servletRequest, id, uriInfo, getLocale());
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new CMSException("Error getting Cert request info!");
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
            RequestId start, int pageSize, int maxResults, int maxTime) {
        // auth and authz

        // get ldap filter
        String filter = createSearchFilter(requestState, requestType);
        CMS.debug("listRequests: filter is " + filter);

        // get start marker
        if (start == null) {
            start = new RequestId(CertRequestResource.DEFAULT_START);
        }

        CertRequestDAO reqDAO = new CertRequestDAO();
        CertRequestInfos requests;
        try {
            requests =  reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            CMS.debug("listRequests: error in obtaining request results" + e);
            e.printStackTrace();
            throw new CMSException("Error listing cert requests!");
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

}
