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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Nonces;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.cert.RenewalProcessor;
import com.netscape.cms.servlet.cert.RequestProcessor;
import com.netscape.cms.servlet.processors.Processor;
import com.netscape.cms.servlet.request.RequestNotFoundException;


/**
 * @author alee
 *
 */
public class CertRequestDAO extends CMSRequestDAO {
    private IRequestQueue queue;
    private ICertificateAuthority ca;
    IProfileSubsystem ps;
    private Nonces nonces = null;
    private Random random = null;

    public static final String ATTR_SERIALNO = "serialNumber";

    public CertRequestDAO() {
        super("ca");
        ca = (ICertificateAuthority) CMS.getSubsystem("ca");
        queue = ca.getRequestQueue();
        if (ca.noncesEnabled()) {
            random = new Random();
            nonces = ca.getNonces();
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
     * Gets info for a specific request
     *
     * @param id
     * @return info for specific request
     * @throws EBaseException
     */
    public AgentEnrollmentRequestData reviewRequest(HttpServletRequest servletRequest, RequestId id,
            UriInfo uriInfo, Locale locale) throws EBaseException {
        IRequest request = queue.findRequest(id);
        if (request == null) {
            return null;
        }
        String profileId = request.getExtDataInString("profileId");
        IProfile profile = ps.getProfile(profileId);
        AgentEnrollmentRequestData info = AgentEnrollmentRequestDataFactory.create(request, profile, uriInfo, locale);
        if (ca.noncesEnabled()) {
            addNonce(info, servletRequest);
        }
        return info;
    }

    private void addNonce(AgentEnrollmentRequestData info, HttpServletRequest servletRequest) throws EBaseException {
        if (nonces != null) {
            long n = random.nextLong();
            long m = nonces.addNonce(n, Processor.getSSLClientCertificate(servletRequest));
            if ((n + m) != 0) {
                info.setNonce(Long.toString(m));
            }
        }
    }

    /**
     * Submits an enrollment request and processes it.
     *
     * @param data
     * @return info for the request submitted.
     * @throws EBaseException
     * @throws ServletException
     */
    public CertRequestInfos submitRequest(EnrollmentRequestData data, HttpServletRequest request, UriInfo uriInfo,
            Locale locale) throws EBaseException {
        HashMap<String, Object> results = null;
        if (data.getIsRenewal()) {
            RenewalProcessor processor = new RenewalProcessor("caProfileSubmit", locale);
            results = processor.processRenewal(data, request);
        } else {
            EnrollmentProcessor processor = new EnrollmentProcessor("caProfileSubmit", locale);
            results = processor.processEnrollment(data, request);
        }

        CertRequestInfos ret = new CertRequestInfos();
        ArrayList<CertRequestInfo> infos = new ArrayList<CertRequestInfo>();
        IRequest reqs[] = (IRequest[]) results.get(Processor.ARG_REQUESTS);
        for (IRequest req : reqs) {
            CertRequestInfo info = CertRequestInfoFactory.create(req, uriInfo);
            infos.add(info);
        }
        // TODO - what happens if the errorCode is internal error ?
        ret.setRequests(infos);
        ret.setLinks(null);

        return ret;
    }

    public void changeRequestState(RequestId id, HttpServletRequest request, AgentEnrollmentRequestData data,
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
