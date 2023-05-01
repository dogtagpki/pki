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

import javax.ws.rs.core.Response;

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
import com.netscape.certsrv.cert.AgentCertRequestResource;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 */
public class AgentCertRequestService extends PKIService implements AgentCertRequestResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AgentCertRequestService.class);

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    @Override
    public Response approveRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Approving certificate request " + id.toHexString());

        changeRequestState(id, data, "approve");
        return createNoContentResponse();
    }

    @Override
    public Response rejectRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Rejecting certificate request " + id.toHexString());

        changeRequestState(id, data, "reject");
        return createNoContentResponse();
    }

    @Override
    public Response cancelRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Canceling certificate request " + id.toHexString());

        changeRequestState(id, data, "cancel");
        return createNoContentResponse();
    }

    @Override
    public Response updateRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Updating certificate request " + id.toHexString());

        changeRequestState(id, data, "update");
        return createNoContentResponse();
    }

    @Override
    public Response validateRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Validating certificate request " + id.toHexString());

        changeRequestState(id, data, "validate");
        return createNoContentResponse();
    }

    @Override
    public Response unassignRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Unassigning certificate request " + id.toHexString());

        changeRequestState(id, data, "unassign");
        return createNoContentResponse();
    }

    @Override
    public Response assignRequest(RequestId id, CertReviewResponse data) {

        logger.info("CertRequestService: Assigning certificate request " + id.toHexString());

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
            logger.error("CertRequestService: Unable to change request state: " + e.getMessage(), e);
            throw new PKIException("Unable to change request state: " + e.getMessage(), e);

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
    public Response reviewRequest(RequestId id) {

        if (id == null) {
            String message = "Unable to review cert request: Missing request ID";
            logger.error(message);
            throw new BadRequestException(message);
        }

        logger.info("CertRequestService: Reviewing certificate request " + id.toHexString());
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

        logger.info("CertRequestService: - profile: " + info.getProfileName());
        logger.info("CertRequestService: - type: " + info.getRequestType());
        logger.info("CertRequestService: - status: " + info.getRequestStatus());

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

        start = start == null ? new RequestId(AgentCertRequestService.DEFAULT_START) : start;
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

    String createSearchFilter(String requestState, String requestType) {
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
