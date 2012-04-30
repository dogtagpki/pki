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
package com.netscape.cms.servlet.request.model;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.cert.CertResource;
import com.netscape.cms.servlet.request.CertRequestResource;

/**
 * @author alee
 *
 */
public class CertRequestDAO extends CMSRequestDAO {
    private IRequestQueue queue;
    private ICertificateAuthority ca;

    public static final String ATTR_SERIALNO = "serialNumber";
    private static final String REQ_COMPLETE = "complete";

    public CertRequestDAO() {

        super("ca");
        ca = (ICertificateAuthority) CMS.getSubsystem("ca");
        queue = ca.getRequestQueue();

    }

    /**
     * Finds list of requests matching the specified search filter.
     *
     * If the filter corresponds to a VLV search, then that search is executed and the pageSize
     * and start parameters are used. Otherwise, the maxResults and maxTime parameters are
     * used in the regularly indexed search.
     *
     * @param filter - ldap search filter
     * @param start - start position for VLV search
     * @param pageSize - page size for VLV search
     * @param maxResults - max results to be returned in normal search
     * @param maxTime - max time for normal search
     * @param uriInfo - uri context of request
     * @return collection of key request info
     * @throws EBaseException
     */

    @SuppressWarnings("unchecked")
    public CertRequestInfos listRequests(String filter, RequestId start, int pageSize, int maxResults, int maxTime,
            UriInfo uriInfo) throws EBaseException {

        CMSRequestInfos cmsInfos = listCMSRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);

        CertRequestInfos ret = new CertRequestInfos();

        if (cmsInfos == null) {
            ret.setRequests(null);
            ret.setLinks(null);
            return ret;
        }

        List<CertRequestInfo> list = new ArrayList<CertRequestInfo>();
        ;
        Collection<? extends CMSRequestInfo> cmsList = cmsInfos.getRequests();

        // We absolutely know 100% that this list is a list
        // of CertRequestInfo objects. This is because the method
        // createCMSRequestInfo. Is the only one adding to it

        list = (List<CertRequestInfo>) cmsList;

        ret.setLinks(cmsInfos.getLinks());
        ret.setRequests(list);

        return ret;
    }

    /**
     * Gets info for a specific request
     *
     * @param id
     * @return info for specific request
     * @throws EBaseException
     */
    public CertRequestInfo getRequest(RequestId id, UriInfo uriInfo) throws EBaseException {
        IRequest request = queue.findRequest(id);
        if (request == null) {
            return null;
        }
        CertRequestInfo info = createCMSRequestInfo(request, uriInfo);
        return info;
    }

    /**
     * Submits an enrollment request and processes it.
     *
     * @param data
     * @return info for the request submitted.
     * @throws EBaseException
     */
    public CertRequestInfo submitRequest(EnrollmentRequestData data, UriInfo uriInfo) throws EBaseException {

        //TODO perform actual profile request.

        throw new EBaseException("Not implemented.");
    }

    public void approveRequest(RequestId id) throws EBaseException {
        IRequest request = queue.findRequest(id);
        request.setRequestStatus(RequestStatus.APPROVED);
        queue.updateRequest(request);
    }

    public void rejectRequest(RequestId id) throws EBaseException {
        IRequest request = queue.findRequest(id);
        request.setRequestStatus(RequestStatus.CANCELED);
        queue.updateRequest(request);
    }

    public void cancelRequest(RequestId id) throws EBaseException {
        IRequest request = queue.findRequest(id);
        request.setRequestStatus(RequestStatus.REJECTED);
        queue.updateRequest(request);
    }

    private CertRequestInfo createCertRequestInfo(IRequest request, UriInfo uriInfo) {
        CertRequestInfo ret = new CertRequestInfo();

        String requestType = request.getRequestType();
        String requestStatus = request.getRequestStatus().toString();

        ret.setRequestType(requestType);
        ret.setRequestStatus(requestStatus);

        ret.setCertRequestType(request.getExtDataInString("cert_request_type"));

        Path certRequestPath = CertRequestResource.class.getAnnotation(Path.class);
        RequestId rid = request.getRequestId();

        UriBuilder reqBuilder = uriInfo.getBaseUriBuilder();
        reqBuilder.path(certRequestPath.value() + "/" + rid);
        ret.setRequestURL(reqBuilder.build().toString());

        //Get Cert info if issued.

        String serialNoStr = null;

        if ((requestType != null) && (requestStatus != null)) {
            if (requestStatus.equals(REQ_COMPLETE)) {
                X509CertImpl impl[] = new X509CertImpl[1];
                impl[0] = request.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);

                BigInteger serialNo;
                if (impl[0] != null) {
                    serialNo = impl[0].getSerialNumber();
                    serialNoStr = serialNo.toString();
                }
            }

        }

        if (serialNoStr != null && !serialNoStr.equals("")) {
            Path certPath = CertResource.class.getAnnotation(Path.class);
            UriBuilder certBuilder = uriInfo.getBaseUriBuilder();
            certBuilder.path(certPath.value() + "/" + serialNoStr);
            ret.setCertURL(certBuilder.build().toString());
        }

        return ret;
    }

    @Override
    public CertRequestInfo createCMSRequestInfo(IRequest request, UriInfo uriInfo) {
        return createCertRequestInfo(request, uriInfo);
    }

}
