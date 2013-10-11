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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.cert;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.profile.SSLClientCertProvider;
import com.netscape.cmsutil.ldap.LDAPUtil;

public class EnrollmentProcessor extends CertProcessor {

    public EnrollmentProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    private void setInputsIntoContext(CertEnrollmentRequest data, IProfile profile, IProfileContext ctx) {
        // put profile inputs into a local map
        HashMap<String, String> dataInputs = new HashMap<String, String>();
        for (ProfileInput input : data.getInputs()) {
            for (ProfileAttribute attr : input.getAttributes()) {
                dataInputs.put(attr.getName(), attr.getValue());
            }
        }

        // iterate through inputs in profile and put those in context
        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();
                    if (dataInputs.containsKey(inputName)) {
                        // all subject name parameters start with sn_, no other input parameters do
                        if (inputName.matches("^sn_.*")) {
                            ctx.set(inputName, LDAPUtil.escapeRDNValue(dataInputs.get(inputName)));
                        } else {
                            ctx.set(inputName, dataInputs.get(inputName));
                        }
                    }
                }
            }
        }

    }

    /**
     * Called by the legacy servlets to access the Processor function
     * @param request
     * @return
     * @throws EBaseException
     */
    public HashMap<String, Object> processEnrollment(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        String profileId = (this.profileID == null) ? req.getParameter("profileId") : this.profileID;
        IProfile profile = ps.getProfile(profileId);

        if (profile == null) {
            CMS.debug(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
        }

        CertEnrollmentRequest data = CertEnrollmentRequestFactory.create(cmsReq, profile, locale);
        return processEnrollment(data, cmsReq.getHttpReq());
    }

    /**
     * Process the HTTP request
     * <P>
     *
     * (Certificate Request Processed - either an automated "EE" profile based cert acceptance, or an automated "EE"
     * profile based cert rejection)
     * <P>
     *
     * <ul>
     * <li>http.param profileId ID of profile to use to process request
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     * @exception EBaseException an error has occurred
     */
    public HashMap<String, Object> processEnrollment(CertEnrollmentRequest data, HttpServletRequest request)
            throws EBaseException {

        try {
            if (CMS.debugOn()) {
                HashMap<String,String> params = data.toParams();
                printParameterValues(params);
            }

            CMS.debug("EnrollmentSubmitter: isRenewal false");
            startTiming("enrollment");

            // if we did not configure profileId in xml file,
            // then accept the user-provided one
            String profileId = (this.profileID == null) ? data.getProfileId() : this.profileID;
            CMS.debug("EnrollmentSubmitter: profileId " + profileId);

            IProfile profile = ps.getProfile(profileId);
            if (profile == null) {
                CMS.debug(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            }
            if (!ps.isProfileEnable(profileId)) {
                CMS.debug("EnrollmentSubmitter: Profile " + profileId + " not enabled");
                throw new BadRequestDataException("Profile " + profileId + " not enabled");
            }

            IProfileContext ctx = profile.createContext();
            CMS.debug("EnrollmentSubmitter: set Inputs into profile Context");
            setInputsIntoContext(data, profile, ctx);

            IProfileAuthenticator authenticator = profile.getAuthenticator();
            if (authenticator != null) {
                CMS.debug("EnrollmentSubmitter: authenticator " + authenticator.getName() + " found");
                setCredentialsIntoContext(request, authenticator, ctx);
            }

            // for ssl authentication; pass in servlet for retrieving ssl client certificates
            // insert profile context so that input parameter can be retrieved
            SessionContext context = SessionContext.getContext();
            context.put("profileContext", ctx);
            context.put("sslClientCertProvider", new SSLClientCertProvider(request));
            CMS.debug("EnrollmentSubmitter: set sslClientCertProvider");

            // before creating the request, authenticate the request
            IAuthToken authToken = authenticate(request, null, authenticator, context, false);

            // authentication success, now authorize
            authorize(profileId, profile, authToken);

            ///////////////////////////////////////////////
            // create and populate request
            ///////////////////////////////////////////////
            startTiming("request_population");
            IRequest[] reqs = profile.createRequests(ctx, locale);
            populateRequests(data, false, locale, null, null, null, profileId, profile,
                    ctx, authenticator, authToken, reqs);
            endTiming("request_population");

            ///////////////////////////////////////////////
            // submit request
            ///////////////////////////////////////////////
            String errorCode = submitRequests(locale, profile, authToken, reqs);
            String errorReason = codeToReason(locale, errorCode);

            HashMap<String, Object> ret = new HashMap<String, Object>();
            ret.put(ARG_REQUESTS, reqs);
            ret.put(ARG_ERROR_CODE, errorCode);
            ret.put(ARG_ERROR_REASON, errorReason);
            ret.put(ARG_PROFILE, profile);

            CMS.debug("EnrollmentSubmitter: done serving");
            endTiming("enrollment");

            return ret;
        } finally {
            SessionContext.releaseContext();
            endAllEvents();
        }
    }




}
