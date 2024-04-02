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

import java.security.Principal;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.CMSRequestInfos;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.authentication.DirBasedAuthentication;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.cert.CertRequestInfoFactory;
import com.netscape.cms.servlet.cert.CertReviewResponseFactory;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.cert.RenewalProcessor;
import com.netscape.cms.servlet.cert.RequestProcessor;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cms.servlet.request.CMSRequestDAO;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * @author alee
 *
 */
public class CertRequestDAO extends CMSRequestDAO {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRequestDAO.class);

    ProfileSubsystem ps;
    private SecureRandom random = null;

    public static final String ATTR_SERIALNO = "serialNumber";

    public CertRequestDAO() {

        CAEngine engine = CAEngine.getInstance();
        requestRepository = engine.getRequestRepository();
        queue = engine.getRequestQueue();

        if (engine.getEnableNonces()) {
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            random = jssSubsystem.getRandomNumberGenerator();
        }

        ps = engine.getProfileSubsystem();
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
        Request request = requestRepository.readRequest(id);
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

        Request request = requestRepository.readRequest(id);

        if (request == null) {
            return null;
        }

        String profileId = request.getExtDataInString(Request.PROFILE_ID);

        CAEngine engine = CAEngine.getInstance();
        Profile profile = ps.getProfile(profileId);
        CertReviewResponse info = CertReviewResponseFactory.create(request, profile, uriInfo, locale);

        if (engine.getEnableNonces()) {
            // generate nonce
            long n = random.nextLong();
            logger.info("CertRequestDAO: Nonce: " + n);

            // store nonce in session
            Map<Object, Long> nonces = engine.getNonces(servletRequest, "cert-request");
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
     * @throws Exception
     */
    public CertRequestInfos submitRequest(
            AuthorityID aid,
            CertEnrollmentRequest data,
            HttpServletRequest request,
            UriInfo uriInfo,
            Locale locale)
        throws Exception {

        CertRequestInfos ret = new CertRequestInfos();

        AuthCredentials credentials = new AuthCredentials();
        String uid = data.getAttribute(DirBasedAuthentication.CRED_UID);
        if (uid != null) {
            credentials.set(DirBasedAuthentication.CRED_UID, uid);
        }
        String password = data.getAttribute(DirBasedAuthentication.CRED_PWD);
        if (password != null) {
            credentials.set(DirBasedAuthentication.CRED_PWD, password);
        }

        CAEngine engine = CAEngine.getInstance();

        HashMap<String, Object> results = null;
        if (data.isRenewal()) {
            RenewalProcessor processor = new RenewalProcessor("caProfileSubmit", locale);
            processor.setCMSEngine(engine);
            processor.init();

            results = processor.processRenewal(data, request, credentials);

        } else {
            EnrollmentProcessor processor = new EnrollmentProcessor("caProfileSubmit", locale);
            processor.setCMSEngine(engine);
            processor.init();

            results = processor.processEnrollment(data, request, aid, credentials);
        }

        Request reqs[] = (Request[]) results.get(CAProcessor.ARG_REQUESTS);
        for (Request req : reqs) {
            try {
                CertRequestInfo info = CertRequestInfoFactory.create(req, uriInfo);
                ret.addEntry(info);
            } catch (NoSuchMethodException e) {
                logger.warn("Error in creating certrequestinfo - no such method: " + e.getMessage(), e);
            }
        }

        ret.setTotal(ret.getEntries().size());

        // TODO - what happens if the errorCode is internal error ?

        return ret;
    }

    public void changeRequestState(RequestId id, HttpServletRequest request, CertReviewResponse data,
            Locale locale, String op) throws EBaseException {
        Request ireq = requestRepository.readRequest(id);
        if (ireq == null) {
            throw new RequestNotFoundException(id);
        }

        CAEngine engine = CAEngine.getInstance();

        RequestProcessor processor = new RequestProcessor("caProfileProcess", locale);
        processor.setCMSEngine(engine);
        processor.init();

        AuthToken authToken = null;

        Principal principal = request.getUserPrincipal();
        if (principal instanceof PKIPrincipal) {
            logger.debug("CertRequestDAO: getting auth token from user principal");
            authToken = ((PKIPrincipal) principal).getAuthToken();
        }

        String authMgr = processor.getAuthenticationManager();
        if (authToken == null && authMgr != null) {
            logger.debug("CertRequestDAO: getting auth token from " + authMgr);
            authToken = processor.authenticate(request);
        }

        logger.debug("CertRequestDAO: auth token: " + authToken);

        processor.processRequest(request, authToken, data, ireq, op);
    }

    @Override
    public CertRequestInfo createCMSRequestInfo(Request request, UriInfo uriInfo) {
        try {
            return CertRequestInfoFactory.create(request, uriInfo);
        } catch (NoSuchMethodException e) {
            logger.warn("Error in creating certrequestinfo - no such method: " + e.getMessage(), e);
        }
        return null;
    }

}
