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

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.ProfileAuthenticator;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.input.SerialNumRenewInput;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.profile.SSLClientCertProvider;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.registry.PluginRegistry;

public class RenewalProcessor extends CertProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RenewalProcessor.class);

    public RenewalProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    /*
     * Renewal - Renewal is retrofitted into the Profile Enrollment
     * Framework.  The authentication and authorization are taken from
     * the renewal profile, while the input (with requests)  and grace
     * period constraint are taken from the original cert's request record.
     *
     * Things to note:
     * * the renew request will contain the original profile instead of the new
     */
    public HashMap<String, Object> processRenewal(
            CertEnrollmentRequest data,
            HttpServletRequest request,
            AuthCredentials credentials)
            throws Exception {
        try {
            if (logger.isDebugEnabled()) {
                HashMap<String, String> params = data.toParams();
                printParameterValues(params);
            }

            logger.debug("RenewalProcessor: processRenewal()");

            CAEngine engine = CAEngine.getInstance();

            startTiming("enrollment");
            request.setAttribute("reqType", "renewal");

            // in case of renew, "profile" is the orig profile
            // while "renewProfile" is the current profile used for renewal
            String renewProfileId = (this.profileID == null) ? data.getProfileId() : this.profileID;
            logger.debug("RenewalProcessor: profile: " + renewProfileId);

            Profile renewProfile = ps.getProfile(renewProfileId);
            if (renewProfile == null) {
                logger.error(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND",
                        CMSTemplate.escapeJavaScriptStringHTML(renewProfileId)));
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND",CMSTemplate.escapeJavaScriptStringHTML(renewProfileId)));
            }
            if (!ps.isProfileEnable(renewProfileId)) {
                logger.error("RenewalProcessor: Profile " + renewProfileId + " not enabled");
                throw new BadRequestDataException("Profile " + renewProfileId + " not enabled");
            }

            BigInteger certSerial = null;

            // get serial number from <SerialNumber> element (no auth required)
            CertId serial = data.getSerialNum();
            if (serial != null) {
                logger.debug("RenewalProcessor: serial number: " + serial);
                certSerial = serial.toBigInteger();
            }

            // if not found, get serial number from profile input (no auth required)
            if (certSerial == null) {

                PluginRegistry registry = engine.getPluginRegistry();

                // find SerialNumRenewInput
                for (ProfileInput input : data.getInputs()) {

                    String inputId = input.getId();
                    if (inputId == null) {
                        throw new BadRequestException("Missing input ID");
                    }

                    String classId = input.getClassId();
                    if (classId == null) {
                        throw new BadRequestException("Missing class ID in input " + inputId);
                    }

                    IPluginInfo pluginInfo = registry.getPluginInfo("profileInput", classId);
                    if (pluginInfo == null) {
                        throw new BadRequestException("Unregistered class ID " + classId + " in input " + inputId);
                    }

                    String className = pluginInfo.getClassName();
                    if (!SerialNumRenewInput.class.getName().equals(className)) {
                        // check the next input
                        continue;
                    }

                    logger.debug("RenewalProcessor: found SerialNumRenewInput");
                    ProfileAttribute attribute = input.getAttribute(SerialNumRenewInput.SERIAL_NUM);

                    if (attribute == null) {
                        throw new BadRequestException("Missing attribute " + SerialNumRenewInput.SERIAL_NUM + " in input " + inputId);
                    }

                    String value = attribute.getValue();
                    logger.debug("RenewalProcessor: profile input " + SerialNumRenewInput.SERIAL_NUM + " value: " + value);

                    if (!StringUtils.isEmpty(value)) {
                        serial = new CertId(value);
                        certSerial = serial.toBigInteger();
                        break;
                    }
                }
            }

            // if still not found, get serial number from client certificate (if provided)
            if (certSerial == null) {

                if (!request.isSecure()) {
                    throw new BadRequestException("Missing serial number");
                }

                // ssl client auth is to be used
                // this is not authentication. Just use the cert to search
                // for orig request and find the right profile
                logger.debug("RenewalProcessor: get serial number from client certificate");
                certSerial = getSerialNumberFromCert(request);
            }

            logger.debug("processRenewal: serial number of cert to renew:" + certSerial.toString());
            ICertRecord rec = certdb.readCertificateRecord(certSerial);
            if (rec == null) {
                logger.error("processRenewal: cert record not found for serial number " + certSerial);
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            }

            // check to see if the cert is revoked or revoked_expired
            if ((rec.getStatus().equals(ICertRecord.STATUS_REVOKED))
                    || (rec.getStatus().equals(ICertRecord.STATUS_REVOKED_EXPIRED))) {
                logger.error("processRenewal: cert found to be revoked. Serial number: " + certSerial);
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_CA_CANNOT_RENEW_REVOKED_CERT"));
            }

            X509CertImpl origCert = rec.getCertificate();
            if (origCert == null) {
                logger.error("processRenewal: original cert not found in cert record for serial number " + certSerial);
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            }

            Date origNotAfter = origCert.getNotAfter();
            logger.debug("processRenewal: origNotAfter =" + origNotAfter.toString());

            String origSubjectDN = origCert.getSubjectDN().getName();
            logger.debug("processRenewal: orig subj dn =" + origSubjectDN);

            IRequest origReq = getOriginalRequest(certSerial, rec);
            if (origReq == null) {
                logger.error("processRenewal: original request not found");
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            }

            String profileId = origReq.getExtDataInString(IRequest.PROFILE_ID);
            logger.debug("RenewalSubmitter: renewal original profileId=" + profileId);

            String aidString = origReq.getExtDataInString(
                    IRequest.AUTHORITY_ID);

            Integer origSeqNum = origReq.getExtDataInInteger(EnrollProfile.REQUEST_SEQ_NUM);
            Profile profile = ps.getProfile(profileId);
            if (profile == null) {
                logger.error(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND",CMSTemplate.escapeJavaScriptStringHTML(profileId)));
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", CMSTemplate.escapeJavaScriptStringHTML(profileId)));
            }
            if (!ps.isProfileEnable(profileId)) {
                logger.error("RenewalSubmitter: Profile " + profileId + " not enabled");
                throw new BadRequestDataException("Profile " + profileId + " not enabled");
            }

            Map<String, String> ctx = new HashMap<>();

            if (aidString != null)
                ctx.put(EnrollProfile.REQUEST_AUTHORITY_ID, aidString);

            ProfileAuthenticator authenticator = ps.getProfileAuthenticator(renewProfile);
            ProfileAuthenticator origAuthenticator = ps.getProfileAuthenticator(profile);

            if (authenticator != null) {
                logger.debug("RenewalSubmitter: authenticator " + authenticator.getName() + " found");
                setCredentialsIntoContext(request, credentials, authenticator, ctx);
            }

            // for renewal, this will override or add auth info to the profile context
            if (origAuthenticator != null) {
                logger.debug("RenewalSubmitter: for renewal, original authenticator " +
                        origAuthenticator.getName() + " found");
                setCredentialsIntoContext(request, credentials, origAuthenticator, ctx);
            }

            // for renewal, input needs to be retrieved from the orig req record
            logger.debug("processRenewal: set original Inputs into profile Context");
            setInputsIntoContext(origReq, profile, ctx, locale);
            ctx.put(EnrollProfile.CTX_RENEWAL, "true");
            ctx.put("renewProfileId", renewProfileId);
            ctx.put(EnrollProfile.CTX_RENEWAL_SEQ_NUM, origSeqNum.toString());

            // for ssl authentication; pass in servlet for retrieving
            // ssl client certificates
            SessionContext context = SessionContext.getContext();
            context.put("profileContext", ctx);
            context.put("sslClientCertProvider", new SSLClientCertProvider(request));
            logger.debug("RenewalSubmitter: set sslClientCertProvider");
            if (origSubjectDN != null)
                context.put("origSubjectDN", origSubjectDN);

            // before creating the request, authenticate the request
            IAuthToken authToken = null;
            Principal principal = request.getUserPrincipal();
            if (principal instanceof PKIPrincipal)
                authToken = ((PKIPrincipal) principal).getAuthToken();
            if (authToken == null && authenticator != null) {
                authToken = authenticate(request, origReq, authenticator, context, true, credentials);
            }

            // authentication success, now authorize
            authorize(profileId, renewProfile, authToken);

            ///////////////////////////////////////////////
            // create and populate requests
            ///////////////////////////////////////////////
            startTiming("request_population");
            IRequest[] reqs = profile.createRequests(ctx, locale);
            populateRequests(data, true, locale, origNotAfter, origSubjectDN, origReq, profileId,
                    profile, ctx, authenticator, authToken, reqs);
            endTiming("request_population");

            ///////////////////////////////////////////////
            // submit request
            ///////////////////////////////////////////////
            String errorCode = submitRequests(locale, profile, authToken, reqs);
            String errorReason = null;

            List<String> errors = new ArrayList<String>();
            if (errorCode != null) {
                for (IRequest req: reqs) {
                    String error = req.getError(locale);
                    if (error != null) {
                        String code = req.getErrorCode(locale);
                        errors.add(codeToReason(locale, code, error, req.getRequestId()));
                    }
                }
                errorReason = StringUtils.join(errors, '\n');
            }

            HashMap<String, Object> ret = new HashMap<String, Object>();
            ret.put(ARG_REQUESTS, reqs);
            ret.put(ARG_ERROR_CODE, errorCode);
            ret.put(ARG_ERROR_REASON, errorReason);
            ret.put(ARG_PROFILE, profile);

            logger.debug("RenewalSubmitter: done serving");
            endTiming("enrollment");

            return ret;
        } finally {
            SessionContext.releaseContext();
            endAllEvents();
        }
    }

    private BigInteger getSerialNumberFromCert(HttpServletRequest request) throws EBaseException {

        SSLClientCertProvider sslCCP = new SSLClientCertProvider(request);
        X509Certificate[] certs = sslCCP.getClientCertificateChain();

        if (certs == null || certs.length == 0) {
            logger.error("RenewalProcessor: missing SSL client certificate chain");
            throw new BadRequestException("Missing SSL client certificate chain");
        }

        logger.debug("RenewalProcessor: has SSL client cert chain");
        // shouldn't expect leaf cert to be always at the
        // same location

        X509Certificate clientCert = null;
        for (X509Certificate cert : certs) {

            logger.debug("RenewalProcessor: cert " + cert.getSubjectDN());
            clientCert = cert;

            byte[] extBytes = clientCert.getExtensionValue("2.5.29.19");

            // try to see if this is a leaf cert
            // look for BasicConstraint extension
            if (extBytes == null) {
                // found leaf cert
                logger.debug("RenewalProcessor: found leaf cert");
                break;
            }

            logger.debug("RenewalProcessor: found cert having BasicConstraints ext");
            // it's got BasicConstraints extension
            // so it's not likely to be a leaf cert,
            // however, check the isCA field regardless

            try {
                BasicConstraintsExtension bce = new BasicConstraintsExtension(true, extBytes);
                if (!(Boolean) bce.get("is_ca")) {
                    logger.debug("RenewalProcessor: found CA cert in chain");
                    break;
                } // else found a ca cert, continue

            } catch (Exception e) {
                logger.error("RenewalProcessor: Invalid certificate extension:" + e.getMessage(), e);
                throw new BadRequestException("Invalid certificate extension: " + e.getMessage(), e);
            }
        }

        // clientCert cannot be null here

        return clientCert.getSerialNumber();
    }

    /*
     * fill input info from "request" to context.
     * This is expected to be used by renewal where the request
     * is retrieved from request record
     */
    private void setInputsIntoContext(IRequest request, Profile profile, Map<String, String> ctx, Locale locale) {
        // passing inputs into context
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();
                    String inputValue = "";
                    logger.debug("RenewalSubmitter: setInputsIntoContext() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        logger.warn("RenewalSubmitter: setInputsIntoContext() getvalue() failed: " + e.getMessage(), e);
                    }

                    if (inputValue != null) {
                        logger.debug("RenewalSubmitter: setInputsIntoContext() setting value in ctx:" + inputValue);
                        ctx.put(inputName, inputValue);
                    } else {
                        logger.warn("RenewalSubmitter: setInputsIntoContext() value null");
                    }
                }
            }
        }

    }

}
