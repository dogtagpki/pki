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
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.profile.SSLClientCertProvider;

public class RenewalProcessor extends CertProcessor {

    public RenewalProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    public HashMap<String, Object> processRenewal(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        String profileId = (this.profileID == null) ? req.getParameter("profileId") : this.profileID;
        IProfile profile = ps.getProfile(profileId);
        if (profile == null) {
            throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
        }

        CertEnrollmentRequest data = CertEnrollmentRequestFactory.create(cmsReq, profile, locale);

        //only used in renewal
        data.setSerialNum(req.getParameter("serial_num"));

        return processRenewal(data, req);
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
    public HashMap<String, Object> processRenewal(CertEnrollmentRequest data, HttpServletRequest request)
            throws EBaseException {
        try {
            if (CMS.debugOn()) {
                HashMap<String,String> params = data.toParams();
                printParameterValues(params);
            }
            CMS.debug("RenewalSubmitter: isRenewal true");

            startTiming("enrollment");
            request.setAttribute("reqType", "renewal");

            // in case of renew, "profile" is the orig profile
            // while "renewProfile" is the current profile used for renewal
            String renewProfileId = (this.profileID == null) ? data.getProfileId() : this.profileID;
            CMS.debug("processRenewal: renewProfileId " + renewProfileId);

            IProfile renewProfile = ps.getProfile(renewProfileId);
            if (renewProfile == null) {
                CMS.debug(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", renewProfileId));
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", renewProfileId));
            }
            if (!ps.isProfileEnable(renewProfileId)) {
                CMS.debug("RenewalSubmitter: Profile " + renewProfileId + " not enabled");
                throw new BadRequestDataException("Profile " + renewProfileId + " not enabled");
            }

            String serial = data.getSerialNum();
            BigInteger certSerial = null;

            if (serial != null) {
                // if serial number is sent with request, then the authentication
                // method is not ssl client auth.  In this case, an alternative
                // authentication method is used (default: ldap based)
                // usr_origreq evaluator should be used to authorize ownership
                // of the cert
                CMS.debug("RenewalSubmitter: renewal: found serial_num");
                certSerial = new BigInteger(serial);
            } else {
                // ssl client auth is to be used
                // this is not authentication. Just use the cert to search
                // for orig request and find the right profile
                CMS.debug("RenewalSubmitter: renewal: serial_num not found, must do ssl client auth");
                certSerial = getSerialNumberFromCert(request);
                if (certSerial == null) {
                    CMS.debug(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
                    throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
                }
            }
            CMS.debug("processRenewal: serial number of cert to renew:" + certSerial.toString());
            ICertRecord rec = certdb.readCertificateRecord(certSerial);
            if (rec == null) {
                CMS.debug("processRenewal: cert record not found for serial number " + certSerial.toString());
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            }

            // check to see if the cert is revoked or revoked_expired
            if ((rec.getStatus().equals(ICertRecord.STATUS_REVOKED))
                    || (rec.getStatus().equals(ICertRecord.STATUS_REVOKED_EXPIRED))) {
                CMS.debug("processRenewal: cert found to be revoked. Serial number = "
                        + certSerial.toString());
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_CA_CANNOT_RENEW_REVOKED_CERT"));
            }

            X509CertImpl origCert = rec.getCertificate();
            if (origCert == null) {
                CMS.debug("processRenewal: original cert not found in cert record for serial number "
                        + certSerial.toString());
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            }

            Date origNotAfter = origCert.getNotAfter();
            CMS.debug("processRenewal: origNotAfter =" + origNotAfter.toString());

            String origSubjectDN = origCert.getSubjectDN().getName();
            CMS.debug("processRenewal: orig subj dn =" + origSubjectDN);

            IRequest origReq = getOriginalRequest(certSerial, rec);
            if (origReq == null) {
                CMS.debug("processRenewal: original request not found");
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_INTERNAL_ERROR"));
            }

            String profileId = origReq.getExtDataInString("profileId");
            CMS.debug("RenewalSubmitter: renewal original profileId=" + profileId);

            Integer origSeqNum = origReq.getExtDataInInteger(IEnrollProfile.REQUEST_SEQ_NUM);
            IProfile profile = ps.getProfile(profileId);
            if (profile == null) {
                CMS.debug(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            }
            if (!ps.isProfileEnable(profileId)) {
                CMS.debug("RenewalSubmitter: Profile " + profileId + " not enabled");
                throw new BadRequestDataException("Profile " + profileId + " not enabled");
            }

            IProfileContext ctx = profile.createContext();
            IProfileAuthenticator authenticator = renewProfile.getAuthenticator();
            IProfileAuthenticator origAuthenticator = profile.getAuthenticator();

            if (authenticator != null) {
                CMS.debug("RenewalSubmitter: authenticator " + authenticator.getName() + " found");
                setCredentialsIntoContext(request, authenticator, ctx);
            }

            // for renewal, this will override or add auth info to the profile context
            if (origAuthenticator != null) {
                CMS.debug("RenewalSubmitter: for renewal, original authenticator " +
                        origAuthenticator.getName() + " found");
                setCredentialsIntoContext(request, origAuthenticator, ctx);
            }

            // for renewal, input needs to be retrieved from the orig req record
            CMS.debug("processRenewal: set original Inputs into profile Context");
            setInputsIntoContext(origReq, profile, ctx, locale);
            ctx.set(IEnrollProfile.CTX_RENEWAL, "true");
            ctx.set("renewProfileId", renewProfileId);
            ctx.set(IEnrollProfile.CTX_RENEWAL_SEQ_NUM, origSeqNum.toString());

            // for ssl authentication; pass in servlet for retrieving
            // ssl client certificates
            SessionContext context = SessionContext.getContext();
            context.put("profileContext", ctx);
            context.put("sslClientCertProvider", new SSLClientCertProvider(request));
            CMS.debug("RenewalSubmitter: set sslClientCertProvider");
            if (origSubjectDN != null)
                context.put("origSubjectDN", origSubjectDN);

            // before creating the request, authenticate the request
            IAuthToken authToken = authenticate(request, origReq, authenticator, context, true);

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
            String errorReason = codeToReason(locale, errorCode);

            HashMap<String, Object> ret = new HashMap<String, Object>();
            ret.put(ARG_REQUESTS, reqs);
            ret.put(ARG_ERROR_CODE, errorCode);
            ret.put(ARG_ERROR_REASON, errorReason);
            ret.put(ARG_PROFILE, profile);

            CMS.debug("RenewalSubmitter: done serving");
            endTiming("enrollment");

            return ret;
        } finally {
            SessionContext.releaseContext();
            endAllEvents();
        }
    }

    private BigInteger getSerialNumberFromCert(HttpServletRequest request) throws EBaseException {
        BigInteger certSerial;
        SSLClientCertProvider sslCCP = new SSLClientCertProvider(request);
        X509Certificate[] certs = sslCCP.getClientCertificateChain();
        certSerial = null;
        if (certs == null || certs.length == 0) {
            CMS.debug("RenewalSubmitter: renewal: no ssl client cert chain");
            return null;
        } else { // has ssl client cert
            CMS.debug("RenewalSubmitter: renewal: has ssl client cert chain");
            // shouldn't expect leaf cert to be always at the
            // same location
            X509Certificate clientCert = null;
            for (int i = 0; i < certs.length; i++) {
                clientCert = certs[i];
                byte[] extBytes = clientCert.getExtensionValue("2.5.29.19");
                // try to see if this is a leaf cert
                // look for BasicConstraint extension
                if (extBytes == null) {
                    // found leaf cert
                    CMS.debug("RenewalSubmitter: renewal: found leaf cert");
                    break;
                } else {
                    CMS.debug("RenewalSubmitter: renewal: found cert having BasicConstraints ext");
                    // it's got BasicConstraints extension
                    // so it's not likely to be a leaf cert,
                    // however, check the isCA field regardless
                    try {
                        BasicConstraintsExtension bce =
                                new BasicConstraintsExtension(true, extBytes);
                        if (bce != null) {
                            if (!(Boolean) bce.get("is_ca")) {
                                CMS.debug("RenewalSubmitter: renewal: found CA cert in chain");
                                break;
                            } // else found a ca cert, continue
                        }
                    } catch (Exception e) {
                        CMS.debug("RenewalSubmitter: renewal: exception:" + e.toString());
                        return null;
                    }
                }
            }
            if (clientCert == null) {
                CMS.debug("RenewalSubmitter: renewal: no client cert in chain");
                return null;
            }
            // convert to java X509 cert interface
            try {
                byte[] certEncoded = clientCert.getEncoded();
                clientCert = new X509CertImpl(certEncoded);
            } catch (Exception e) {
                e.printStackTrace();
                CMS.debug("RenewalSubmitter: renewal: exception:" + e.toString());
                return null;
            }

            certSerial = clientCert.getSerialNumber();
        }
        return certSerial;
    }

    /*
     * fill input info from "request" to context.
     * This is expected to be used by renewal where the request
     * is retrieved from request record
     */
    private void setInputsIntoContext(IRequest request, IProfile profile, IProfileContext ctx, Locale locale) {
        // passing inputs into context
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();

                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();
                    String inputValue = "";
                    CMS.debug("RenewalSubmitter: setInputsIntoContext() getting input name= " + inputName);
                    try {
                        inputValue = profileInput.getValue(inputName, locale, request);
                    } catch (Exception e) {
                        CMS.debug("RenewalSubmitter: setInputsIntoContext() getvalue() failed: " + e.toString());
                    }

                    if (inputValue != null) {
                        CMS.debug("RenewalSubmitter: setInputsIntoContext() setting value in ctx:" + inputValue);
                        ctx.set(inputName, inputValue);
                    } else {
                        CMS.debug("RenewalSubmitter: setInputsIntoContext() value null");
                    }
                }
            }
        }

    }

}
