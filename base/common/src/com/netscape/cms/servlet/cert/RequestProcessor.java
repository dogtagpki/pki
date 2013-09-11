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

import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.PolicyDefault;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileOutput;
import com.netscape.certsrv.profile.ProfilePolicySet;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.profile.ProfileOutputFactory;

public class RequestProcessor extends CertProcessor {

    public RequestProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);
    }

    public CertReviewResponse processRequest(CMSRequest cmsReq, IRequest request, String op) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        IRequest ireq = cmsReq.getIRequest();

        String profileId = ireq.getExtDataInString("profileId");
        IProfile profile = ps.getProfile(profileId);
        CertReviewResponse data = CertReviewResponseFactory.create(
                cmsReq, profile, authority.noncesEnabled(), locale);

        processRequest(req, data, request, op);
        return data;
    }

    public void processRequest(HttpServletRequest request, CertReviewResponse data, IRequest req, String op)
            throws EBaseException {
        try {
            startTiming("approval");

            IAuthToken authToken = null;

            if (CMS.debugOn()) {
                HashMap<String, String> params = data.toParams();
                printParameterValues(params);
                CMS.debug("processRequest op is " + op);
            }

            if (authMgr != null) {
                authToken = authenticate(request);
            }

            AuthzToken authzToken = authorize(aclMethod, authToken, authzResourceName, "approve");
            if (authzToken == null) {
                throw new EAuthzException(CMS.getUserMessage(locale, "CMS_AUTHORIZATION_ERROR"));
            }

            if (authority.noncesEnabled()) {
                Object id = data.getRequestId().toBigInteger();

                String requestNonce = data.getNonce();
                if (requestNonce == null) {
                    CMS.debug("RequestProcessor: Missing nonce");
                    throw new BadRequestException("Missing nonce.");
                }

                Long nonce = new Long(requestNonce.trim());
                validateNonce(request, "cert-request", id, nonce);
            }

            CMS.debug("RequestProcessor: processRequest: start serving");

            RequestId requestId = data.getRequestId();
            if (requestId == null || requestId.equals("")) {
                CMS.debug(CMS.getUserMessage(locale, "CMS_REQUEST_ID_NOT_FOUND"));
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_REQUEST_ID_NOT_FOUND"));
            }
            CMS.debug("RequestProcessor: requestId=" + requestId);

            // check if the request is in one of the terminal states
            if (!req.getRequestStatus().equals(RequestStatus.PENDING)) {
                CMS.debug(CMS.getUserMessage(locale, "CMS_REQUEST_NOT_PENDING", requestId.toString()));
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_REQUEST_NOT_PENDING",
                        requestId.toString()));
            }

            // save auth token in request
            saveAuthToken(authToken, req);

            String profileId = req.getExtDataInString("profileId");
            if (profileId == null || profileId.equals("")) {
                CMS.debug("RequestProcessor: Profile Id not found in request");
                throw new EBaseException(CMS.getUserMessage(locale, "CMS_PROFILE_ID_NOT_FOUND"));
            }
            CMS.debug("RequestProcessor: profileId=" + profileId);

            IProfile profile = ps.getProfile(profileId);
            if (profile == null) {
                CMS.debug(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
                throw new BadRequestDataException(CMS.getUserMessage(locale, "CMS_PROFILE_NOT_FOUND", profileId));
            }
            if (!ps.isProfileEnable(profileId)) {
                CMS.debug("RequestProcessor: Profile " + profileId + " not enabled");
                throw new BadRequestDataException("Profile " + profileId + " not enabled");
            }

            if (op.equals("assign")) {
                String owner = req.getRequestOwner();

                // assigned owner
                if (owner != null && owner.length() > 0) {
                    if (!grantPermission(req, authToken)) {
                        CMS.debug("RequestProcessor: Permission not granted to assign request.");
                        throw new EAuthzException(CMS.getUserMessage(locale, "CMS_PROFILE_DENY_OPERATION"));
                    }
                }
                String id = auditSubjectID();
                req.setRequestOwner(id);
            } else {
                if (grantPermission(req, authToken)) {
                    if (op.equals("approve")) {
                        checkProfileVersion(profile, req);
                        updateValues(data, req, profile, locale);
                        updateNotes(data, req);
                        approveRequest(req, data, profile, locale);
                    } else if (op.equals("reject")) {
                        updateNotes(data, req);
                        rejectRequest(req);
                    } else if (op.equals("cancel")) {
                        updateNotes(data, req);
                        cancelRequest(req);
                    } else if (op.equals("update")) {
                        checkProfileVersion(profile, req);
                        updateValues(data, req, profile, locale);
                        updateNotes(data, req);
                    } else if (op.equals("validate")) {
                        updateValues(data, req, profile, locale);
                    } else if (op.equals("unassign")) {
                        req.setRequestOwner("");
                    }
                } else {
                    CMS.debug("RequestProcessor: Permission not granted to approve/reject/cancel/update/validate/unassign request.");
                    throw new EAuthzException(CMS.getUserMessage(locale, "CMS_PROFILE_DENY_OPERATION"));
                }
            }

            // commit request to the storage
            if (!op.equals("validate")) {
                if (op.equals("approve")) {
                    queue.markAsServiced(req);
                } else {
                    queue.updateRequest(req);
                }
            }
            endTiming("approval");

        } finally {
            endAllEvents();
        }
    }

    private boolean grantPermission(IRequest req, IAuthToken token) {
        boolean enable = false;
        try {
            enable = CMS.getConfigStore().getBoolean("request.assignee.enable", false);
        } catch (EBaseException e) {
        }

        if (!enable)
            return true;
        String owner = req.getRequestOwner();

        // unassigned owner
        if (owner == null || owner.length() == 0)
            return true;
        String uid = token.getInString(IAuthToken.USER_ID);
        if (uid.equals(owner))
            return true;

        return false;
    }

    /**
     * Check if the request creation time is older than the profile
     * lastModified attribute.
     */
    private void checkProfileVersion(IProfile profile, IRequest req) throws EProfileException {
        IConfigStore profileConfig = profile.getConfigStore();
        if (profileConfig != null) {
            String lastModified = null;

            try {
                lastModified = profileConfig.getString("lastModified", "");
            } catch (EBaseException e) {
            }

            if (!lastModified.equals("")) {
                Date profileModifiedAt = new Date(Long.parseLong(lastModified));
                CMS.debug("CertRequestExecutor: Profile Last Modified=" +
                        profileModifiedAt);
                Date reqCreatedAt = req.getCreationTime();
                CMS.debug("CertRequestExecutor: Request Created At=" +
                        reqCreatedAt);
                if (profileModifiedAt.after(reqCreatedAt)) {
                    CMS.debug("Profile Newer Than Request");
                    throw new ERejectException("Profile Newer Than Request");
                }
            }
        }
    }

    /**
     * Cancel request
     * <P>
     *
     * (Certificate Request Processed - a manual "agent" profile based cert cancellation)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     *
     * @param req the certificate request
     * @exception EProfileException an error related to this profile has
     *                occurred
     */
    private void cancelRequest(IRequest req) throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);
        String auditInfoValue = auditInfoValue(req);

        req.setRequestStatus(RequestStatus.CANCELED);

        // store a message in the signed audit log file
        auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                auditSubjectID,
                ILogger.SUCCESS,
                auditRequesterID,
                ILogger.SIGNED_AUDIT_CANCELLATION,
                auditInfoValue);

        audit(auditMessage);
    }

    /**
     * Reject request
     * <P>
     *
     * (Certificate Request Processed - a manual "agent" profile based cert rejection)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     * @param req the certificate request
     * @exception EProfileException an error related to this profile has
     *                occurred
     */
    private void rejectRequest(IRequest req) throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);
        String auditInfoValue = auditInfoValue(req);

        req.setRequestStatus(RequestStatus.REJECTED);

        // store a message in the signed audit log file
        auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                auditSubjectID,
                ILogger.SUCCESS,
                auditRequesterID,
                ILogger.SIGNED_AUDIT_REJECTION,
                auditInfoValue);

        audit(auditMessage);
    }

    /**
     * Approve request
     * <P>
     *
     * (Certificate Request Processed - a manual "agent" profile based cert acceptance)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     * @param request the servlet request
     * @param req the certificate request
     * @param profile this profile
     * @param locale the system locale
     * @exception EProfileException an error related to this profile has
     *                occurred
     */
    private void approveRequest(IRequest req, CertReviewResponse data, IProfile profile, Locale locale)
            throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);

        try {
            profile.execute(req);
            req.setRequestStatus(RequestStatus.COMPLETE);

            Enumeration<String> outputIds = profile.getProfileOutputIds();
            while (outputIds.hasMoreElements()) {
                IProfileOutput output = profile.getProfileOutput(outputIds.nextElement());
                ProfileOutput addOutput = ProfileOutputFactory.create(output, req, locale);
                data.addOutput(addOutput);
            }

            // retrieve the certificate
            X509CertImpl theCert = req.getExtDataInCert(
                    IEnrollProfile.REQUEST_ISSUED_CERT);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditRequesterID,
                    ILogger.SIGNED_AUDIT_ACCEPTANCE,
                    auditInfoCertValue(theCert));

            audit(auditMessage);

        } catch (EProfileException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                    auditSubjectID,
                    ILogger.FAILURE,
                    auditRequesterID,
                    ILogger.SIGNED_AUDIT_ACCEPTANCE,
                    ILogger.SIGNED_AUDIT_EMPTY_VALUE);

            audit(auditMessage);

            CMS.debug("CertRequestExecutor: about to throw EProfileException because of bad profile execute.");
            throw eAudit1;
        }
    }

    private void updateValues(CertReviewResponse data, IRequest req,
            IProfile profile, Locale locale)
            throws ERejectException, EDeferException, EPropertyException {

        // put request policy defaults in a local hash
        HashMap<String, String> policyData = new HashMap<String,String>();
        for (ProfilePolicySet policySet: data.getPolicySets()) {
            for (com.netscape.certsrv.profile.ProfilePolicy policy: policySet.getPolicies()) {
                PolicyDefault def = policy.getDef();
                List<ProfileAttribute> attrs = def.getAttributes();
                for (ProfileAttribute attr: attrs) {
                    policyData.put(attr.getName(), attr.getValue());
                }
            }
        }

        String profileSetId = req.getExtDataInString("profileSetId");

        Enumeration<IProfilePolicy> policies = profile.getProfilePolicies(profileSetId);
        int count = 0;

        while (policies.hasMoreElements()) {
            IProfilePolicy policy = policies.nextElement();

            setValue(locale, count, policy, req, policyData);
            count++;
        }

        policies = profile.getProfilePolicies(profileSetId);
        count = 0;
        while (policies.hasMoreElements()) {
            IProfilePolicy policy = policies.nextElement();

            validate(count, policy, req);
            count++;
        }

    }

    private void updateNotes(CertReviewResponse data, IRequest req) {
        String notes = data.getRequestNotes();

        if (notes != null) {
            req.setExtData("requestNotes", notes);
        }
    }

    private void validate(int count, IProfilePolicy policy, IRequest req)
            throws ERejectException, EDeferException {
        IPolicyConstraint con = policy.getConstraint();

        con.validate(req);
    }

    private void setValue(Locale locale, int count, IProfilePolicy policy, IRequest req,
            HashMap<String, String> data) throws EPropertyException {
        // handle default policy
        IPolicyDefault def = policy.getDefault();
        Enumeration<String> defNames = def.getValueNames();

        while (defNames.hasMoreElements()) {
            String defName = defNames.nextElement();
            String defValue = data.get(defName);

            def.setValue(defName, locale, req, defValue);
        }
    }
}
