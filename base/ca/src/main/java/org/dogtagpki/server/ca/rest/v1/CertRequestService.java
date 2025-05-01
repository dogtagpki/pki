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

package org.dogtagpki.server.ca.rest.v1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

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
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.profile.ProfileSubsystem;

/**
 * @author alee
 */
public class CertRequestService extends PKIService implements CertRequestResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRequestService.class);

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;

    /**
     * Used to retrieve key request info for a specific request
     */
    @Override
    public Response getRequestInfo(RequestId id) {

        if (id == null) {
            String message = "Unable to get certificate request info: Missing request ID";
            logger.error(message);
            throw new BadRequestException(message);
        }

        logger.info("CertRequestService: Retrieving certificate request " + id.toHexString());
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
    public Response enrollCert(String enrollmentRequest, String aidString, String adnString) throws Exception {

        logger.info("CertRequestService: Receiving certificate request");

        CertEnrollmentRequest data = unmarshall(enrollmentRequest, CertEnrollmentRequest.class);

        if (data == null) {
            String message = "Unable to create enrollment request: Missing input data";
            logger.error(message);
            throw new BadRequestException(message);
        }

        if (aidString != null && adnString != null) {
            String message = "Cannot provide both issuer ID and issuer DN";
            logger.error(message);
            throw new BadRequestException(message);
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        AuthorityID aid = null;
        if (aidString != null) {
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                String message = "Invalid authority ID: " + aidString;
                logger.error(message);
                throw new BadRequestException(message, e);
            }

            ca = engine.getCA(aid);

            if (ca == null) {
                String message = "CA not found: " + aidString;
                logger.error(message);
                throw new ResourceNotFoundException(message);
            }
        }

        if (adnString != null) {
            X500Name adn = null;
            try {
                adn = new X500Name(adnString);
            } catch (IOException e) {
                String message = "Invalid DN: " + adnString;
                logger.error(message);
                throw new BadRequestException(message, e);
            }

            ca = engine.getCA(adn);

            if (ca == null) {
                String message = "CA not found: " + adnString;
                logger.error(message);
                throw new ResourceNotFoundException(message);
            }

            aid = ca.getAuthorityID();
        }

        if (!ca.getAuthorityEnabled()) {
            String message = "CA not enabled: " + aid;
            logger.error(message);
            throw new ConflictingOperationException(message);
        }

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

        Enumeration<String> e = ps.getProfileIds();
        if (e == null) return createOKResponse(infos);

        // store non-null results in a list
        List<ProfileDataInfo> results = new ArrayList<>();
        while (e.hasMoreElements()) {
            try {
                String id = e.nextElement();
                ProfileDataInfo info = ProfileService.createProfileDataInfo(id, uriInfo, getLocale(headers));
                if (info == null || !info.getProfileVisible().booleanValue()) {
                    continue;
                }
                results.add(info);
            } catch (EBaseException ex) {
                logger.warn("CertRequestService: {}",  ex.getMessage());
            }
        }

        int total = results.size();
        infos.setTotal(total);

        // return entries in the requested page
        for (int i = start; i < start + size && i < total; i++) {
            infos.addEntry(results.get(i));
        }

        return createOKResponse(infos);
    }
}
