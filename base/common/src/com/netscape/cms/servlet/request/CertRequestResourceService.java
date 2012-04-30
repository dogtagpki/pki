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

import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.BadRequestException;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.request.model.CertRequestDAO;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;

/**
 * @author alee
 *
 */
public class CertRequestResourceService extends CMSResourceService implements CertRequestResource {

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
    public CertRequestInfo enrollCert(MultivaluedMap<String, String> form) {
        EnrollmentRequestData data = new EnrollmentRequestData(form);
        return enrollCert(data);
    }

    public CertRequestInfo enrollCert(EnrollmentRequestData data) {

        if (data == null) {
            throw new BadRequestException("Bad data input into CertRequestResourceService.enrollCert!");
        }
        CertRequestDAO dao = new CertRequestDAO();

        try {
            dao.submitRequest(data, uriInfo);
        } catch (EBaseException e) {
            throw new CMSException("Problem enrolling cert in CertRequestResource.enrollCert!");
        }

        //TODO implement
        throw new CMSException("CertRequestResourceService.enrollCert not implemented!");
    }

    public void approveRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Bad data input in CertRequestResourceService.approveRequest!");
        }
        //TODO implement
        throw new CMSException("Problem approving request in CertRequestResource.approveRequest!");
    }

    public void rejectRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Bad data input into CertRequestResourceService.rejectRequest!");
        }
        //TODO implement

        throw new CMSException("Problem rejecting request in CertRequestResource.rejectRequest!");

    }

    public void cancelRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Bad data input in CertRequestResourceService.cancelRequest!");
        }
        //TODO implement
        throw new CMSException("Problem cancelling request in CertRequestResource.cancelRequest!");
    }
}
