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
package com.netscape.cms.servlet.cert;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.CMSRequestInfos;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cms.servlet.request.CMSRequestDAO;

/**
 * @author alee
 *
 */
public class CertRequestDAO extends CMSRequestDAO {
    private IRequestQueue queue;
    private ICertificateAuthority ca;
    IProfileSubsystem ps;
    private Random random = null;

    public static final String ATTR_SERIALNO = "serialNumber";

    public CertRequestDAO() {
        super("ca");
        ca = (ICertificateAuthority) CMS.getSubsystem("ca");
        queue = ca.getRequestQueue();
        if (ca.noncesEnabled()) {
            random = new Random();
        }
        ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);
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

        CertRequestInfos ret = new CertRequestInfos();

        CMSRequestInfos cmsInfos = listCMSRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);

        ret.setTotal(cmsInfos.getTotal());

        Collection<? extends CMSRequestInfo> cmsList = cmsInfos.getEntries();

        // We absolutely know 100% that this list is a list
        // of CertRequestInfo objects. This is because the method
        // createCMSRequestInfo. Is the only one adding to it

        List<CertRequestInfo> list = (List<CertRequestInfo>) cmsList;
        ret.setEntries(list);

        ret.setLinks(cmsInfos.getLinks());

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
     * Gets info for a specific request
     *
     * @param id
     * @return info for specific request
     * @throws EBaseException
     */
    public CertReviewResponse reviewRequest(HttpServletRequest servletRequest, RequestId id,
            UriInfo uriInfo, Locale locale) throws EBaseException {
        IRequest request = queue.findRequest(id);
        if (request == null) {
            return null;
        }
        String profileId = request.getExtDataInString("profileId");
        IProfile profile = ps.getProfile(profileId);
        CertReviewResponse info = CertReviewResponseFactory.create(request, profile, uriInfo, locale);

        if (ca.noncesEnabled()) {
            // generate nonce
            long n = random.nextLong();

            // store nonce in session
            Map<Object, Long> nonces = ca.getNonces(servletRequest, "cert-request");
            nonces.put(info.getRequestId().toBigInteger(), n);

            // return nonce to client
            info.setNonce(Long.toString(n));
        }
        return info;
    }

    /**
     * Submits an enrollment request and processes it.
     *
     * @param data
     * @return info for the request submitted.
     * @throws EBaseException
     * @throws ServletException
     */
    public CertRequestInfos submitRequest(CertEnrollmentRequest data, HttpServletRequest request, UriInfo uriInfo,
            Locale locale) throws EBaseException {

        CertRequestInfos ret = new CertRequestInfos();

        HashMap<String, Object> results = null;
        if (data.isRenewal()) {
            RenewalProcessor processor = new RenewalProcessor("caProfileSubmit", locale);
            results = processor.processRenewal(data, request);
        } else {
            EnrollmentProcessor processor = new EnrollmentProcessor("caProfileSubmit", locale);
            results = processor.processEnrollment(data, request);
        }

        IRequest reqs[] = (IRequest[]) results.get(CAProcessor.ARG_REQUESTS);
        for (IRequest req : reqs) {
            CertRequestInfo info = CertRequestInfoFactory.create(req, uriInfo);
            ret.addEntry(info);
        }

        ret.setTotal(ret.getEntries().size());

        // TODO - what happens if the errorCode is internal error ?

        return ret;
    }

    public void changeRequestState(RequestId id, HttpServletRequest request, CertReviewResponse data,
            Locale locale, String op) throws EBaseException {
        IRequest ireq = queue.findRequest(id);
        if (ireq == null) {
            throw new RequestNotFoundException(id);
        }

        RequestProcessor processor = new RequestProcessor("caProfileProcess", locale);
        processor.processRequest(request, data, ireq, op);
    }

    @Override
    public CertRequestInfo createCMSRequestInfo(IRequest request, UriInfo uriInfo) {
        return CertRequestInfoFactory.create(request, uriInfo);
    }

}
