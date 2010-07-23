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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.profile;


import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;

import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.template.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.ca.*;
import com.netscape.cms.servlet.common.*;

import java.security.cert.*;
import netscape.security.x509.*;


/**
 * This servlet approves profile-based request.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ProfileProcessServlet extends ProfileServlet {
    private static final String PROP_AUTHORITY_ID = "authorityId";
    private String mAuthorityId = null;
    private Nonces mNonces = null;

    private final static String SIGNED_AUDIT_CERT_REQUEST_REASON =
        "requestNotes";
    private final static String LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED =
        "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";

    public ProfileProcessServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mAuthorityId = sc.getInitParameter(PROP_AUTHORITY_ID);

        ICertificateAuthority authority = null;
        if (mAuthorityId != null)
            authority = (ICertificateAuthority) CMS.getSubsystem(mAuthorityId);

        if (authority != null && authority.noncesEnabled()) {
            mNonces = authority.getNonces();
        }
    }

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        IStatsSubsystem statsSub = (IStatsSubsystem)CMS.getSubsystem("stats");
        if (statsSub != null) {
          statsSub.startTiming("approval", true /* main action */);
        }

        IAuthToken authToken = null;
        ArgSet args = new ArgSet();

        Locale locale = getLocale(request);

        if (mAuthMgr != null) {
            try {
                authToken = authenticate(cmsReq);
            } catch (EBaseException e) {
                CMS.debug("ProfileProcessServlet: " + e.toString());
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
                args.set(ARG_ERROR_CODE, "1"); 
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, 
                        "CMS_AUTHENTICATION_ERROR"));
                outputTemplate(request, response, args);
                if (statsSub != null) {
                  statsSub.endTiming("approval");
                }
                return;
            }
        }

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "approve");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_AUTHORIZATION_ERROR"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        if (mNonces != null) {
            String requestNonce = request.getParameter(ARG_REQUEST_NONCE);
            boolean nonceVerified = false;
            if (requestNonce != null) {
                long nonce = Long.parseLong(requestNonce.trim());
                X509Certificate cert1 = mNonces.getCertificate(nonce);
                X509Certificate cert2 = getSSLClientCertificate(request);
                if (cert1 == null) {
                    CMS.debug("ProfileProcessServlet:  Unknown nonce");
                } else if (cert1 != null && cert2 != null && cert1.equals(cert2)) {
                    nonceVerified = true;
                    mNonces.removeNonce(nonce);
                }
            } else {
                CMS.debug("ProfileProcessServlet:  Missing nonce");
            }
            CMS.debug("ProfileProcessServlet:  nonceVerified="+nonceVerified);
            if (!nonceVerified) {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_AUTHORIZATION_ERROR"));
                outputTemplate(request, response, args);
                if (statsSub != null) {
                    statsSub.endTiming("approval");
                }
                return;
            }
        }

        CMS.debug("ProfileProcessServlet: start serving");

        // (1) Read request from the database

        // (2) Get profile id from the request
        if (mProfileSubId == null || mProfileSubId.equals("")) {
            mProfileSubId = IProfileSubsystem.ID;
        }
        CMS.debug("ProfileProcessServlet: SubId=" + mProfileSubId);
        IProfileSubsystem ps = (IProfileSubsystem)
            CMS.getSubsystem(mProfileSubId);

        if (ps == null) {
            CMS.debug("ProfileProcessServlet: ProfileSubsystem not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        // retrieve request
        IAuthority authority = (IAuthority) CMS.getSubsystem(mAuthorityId);

        if (authority == null) {
            CMS.debug("ProfileProcessServlet: Authority " + mAuthorityId +
                " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }
        IRequestQueue queue = authority.getRequestQueue();

        if (queue == null) {
            CMS.debug("ProfileProcessServlet: Request Queue of " +
                mAuthorityId + " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        String requestId = request.getParameter("requestId");

        if (requestId == null || requestId.equals("")) {
            CMS.debug("ProfileProcessServlet: Request Id not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_REQUEST_ID_NOT_FOUND"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        IRequest req = null;

        CMS.debug("ProfileProcessServlet: requestId=" + requestId);
        try {
            req = queue.findRequest(new RequestId(requestId));
        } catch (EBaseException e) {
            // request not found
            CMS.debug("ProfileProcessServlet: request not found requestId=" + 
                requestId + " " + e.toString());
        }
        if (req == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_REQUEST_NOT_FOUND", requestId));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

	// check if the request is in one of the terminal states
        if (!req.getRequestStatus().equals(RequestStatus.PENDING)) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_REQUEST_NOT_PENDING", requestId));
            args.set(ARG_REQUEST_ID, requestId);
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        String profileId = req.getExtDataInString("profileId");

        CMS.debug("ProfileProcessServlet: profileId=" + profileId);
        if (profileId == null || profileId.equals("")) {
            CMS.debug("ProfileProcessServlet: Profile Id not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_ID_NOT_FOUND"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        String op = request.getParameter("op");
        if (op == null) {
            CMS.debug("ProfileProcessServlet: No op found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_OP_NOT_FOUND"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }


        IProfile profile = null;

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            // profile not found
            CMS.debug("ProfileProcessServlet: profile not found " + 
                " " + " profileId=" + profileId + " " + e.toString());
        }
        if (profile == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }

        // if profile is currently disabled, dont do anything
        if (!ps.isProfileEnable(profileId)) {
            CMS.debug("ProfileProcessServlet: Profile Id not enabled");
            args.set(ARG_OP, op);
            args.set(ARG_REQUEST_ID, req.getRequestId().toString());
            args.set(ARG_REQUEST_STATUS, req.getRequestStatus().toString());
            args.set(ARG_REQUEST_TYPE, req.getRequestType());
            args.set(ARG_PROFILE_ID, profileId);
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_ID_NOT_ENABLED"));
            outputTemplate(request, response, args);
            if (statsSub != null) {
              statsSub.endTiming("approval");
            }
            return;
        }


        args.set(ARG_ERROR_CODE, "0");
        args.set(ARG_ERROR_REASON, "");

        try {
            if (op.equals("assign")) {
                String owner = req.getRequestOwner();

                // assigned owner 
                if (owner != null && owner.length() > 0) {
                    if (!grantPermission(req, authToken)) {
                        CMS.debug("ProfileProcessServlet: Permission not granted to assign request.");
                        args.set(ARG_OP, op);
                        args.set(ARG_REQUEST_ID, req.getRequestId().toString());
                        args.set(ARG_REQUEST_STATUS, req.getRequestStatus().toString());
                        args.set(ARG_REQUEST_TYPE, req.getRequestType());
                        args.set(ARG_PROFILE_ID, profileId);
                        args.set(ARG_PROFILE_ID, profileId);
                        args.set(ARG_ERROR_CODE, "1");
                        args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_DENY_OPERATION"));
                        outputTemplate(request, response, args);
                        if (statsSub != null) {
                          statsSub.endTiming("approval");
                        }
                        return;
                    }
                }
                assignRequest(request, args, req, queue, profile, locale);
            } else {
                if (grantPermission(req, authToken)) {
                    if (op.equals("approve")) {
                        checkProfileVersion(profile, req, locale);
                        updateValues(request, req, queue, profile, locale);
                        updateNotes(request, req);
                        approveRequest(request, args, req, queue, profile, locale);
                    } else if (op.equals("reject")) {
                        updateNotes(request, req);
                        rejectRequest(request, args, req, queue, profile, locale);
                    } else if (op.equals("cancel")) {
                        updateNotes(request, req);
                        cancelRequest(request, args, req, queue, profile, locale);
                    } else if (op.equals("update")) {
                        checkProfileVersion(profile, req, locale);
                        updateValues(request, req, queue, profile, locale);
                        updateNotes(request, req);
                    } else if (op.equals("validate")) {
                        updateValues(request, req, queue, profile, locale);
                    } else if (op.equals("unassign")) {
                        unassignRequest(request, args, req, queue, profile, locale);
                    }
                } else {
                    CMS.debug("ProfileProcessServlet: Permission not granted to approve/reject/cancel/update/validate/unassign request.");
                    args.set(ARG_OP, op);
                    args.set(ARG_REQUEST_ID, req.getRequestId().toString());
                    args.set(ARG_REQUEST_STATUS, req.getRequestStatus().toString());
                    args.set(ARG_REQUEST_TYPE, req.getRequestType());
                    args.set(ARG_PROFILE_ID, profileId);
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale, "CMS_PROFILE_DENY_OPERATION"));
                    outputTemplate(request, response, args);
                    if (statsSub != null) {
                      statsSub.endTiming("approval");
                    }
                    return;
                }
            }

            // commit request to the storage
            if (!op.equals("validate")) { 
                try {
                    queue.updateRequest(req);
                } catch (EBaseException e) {
                    CMS.debug("ProfileProcessServlet: Request commit error " + 
                        e.toString());
                    // save request to disk
                    args.set(ARG_ERROR_CODE, "1");
                    args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                            "CMS_INTERNAL_ERROR"));
                    outputTemplate(request, response, args);
                    if (statsSub != null) {
                      statsSub.endTiming("approval");
                    }
                    return;
                }
            }
        } catch (ERejectException e) {
            CMS.debug("ProfileProcessServlet: execution rejected " + 
                e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_REJECTED", e.toString()));
        } catch (EDeferException e) {
            CMS.debug("ProfileProcessServlet: execution defered " + 
                e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_DEFERRED", e.toString()));
        } catch (EPropertyException e) {
            CMS.debug("ProfileProcessServlet: execution error " + 
                e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_PROPERTY_ERROR", e.toString()));
        } catch (EProfileException e) {
            CMS.debug("ProfileProcessServlet: execution error " + 
                e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
        }

        args.set(ARG_OP, op);
        args.set(ARG_REQUEST_ID, req.getRequestId().toString());
        args.set(ARG_REQUEST_STATUS, req.getRequestStatus().toString());
        args.set(ARG_REQUEST_TYPE, req.getRequestType());
        args.set(ARG_PROFILE_ID, profileId);
        outputTemplate(request, response, args);
        if (statsSub != null) {
          statsSub.endTiming("approval");
        }
    }
 
    public boolean grantPermission(IRequest req, IAuthToken token) {

        try {
            boolean enable = CMS.getConfigStore().getBoolean("request.assignee.enable",
              false);
            if (!enable)
                return true;
            String owner = req.getRequestOwner();

            // unassigned owner
            if (owner == null || owner.length() == 0)
                return true;
            String uid = token.getInString(IAuthToken.USER_ID);
            if (uid.equals(owner))
                return true;
        } catch (Exception e) {
        }
   
        return false;
    }

    /**
     * Check if the request creation time is older than the profile
     * lastModified attribute. 
     */
    protected void checkProfileVersion(IProfile profile, IRequest req, 
        Locale locale) throws EProfileException {
        IConfigStore profileConfig = profile.getConfigStore();
        if (profileConfig != null) {
            String lastModified = null;
            try {
              lastModified = profileConfig.getString("lastModified","");
            } catch (EBaseException e) {
              CMS.debug(e.toString());
              throw new EProfileException( e.toString() );
            }
            if (!lastModified.equals("")) {
                Date profileModifiedAt = new Date(Long.parseLong(lastModified));
                CMS.debug("ProfileProcessServlet: Profile Last Modified=" + 
                  profileModifiedAt);
                Date reqCreatedAt = req.getCreationTime();
                CMS.debug("ProfileProcessServlet: Request Created At=" + 
                   reqCreatedAt);
                if (profileModifiedAt.after(reqCreatedAt)) {
                    CMS.debug("Profile Newer Than Request");
                    throw new ERejectException("Profile Newer Than Request");
                }
            }
        }
    }

    protected void assignRequest(ServletRequest request, ArgSet args,
        IRequest req, 
        IRequestQueue queue, IProfile profile, Locale locale)
        throws EProfileException {

        String id = auditSubjectID();
        req.setRequestOwner(id);
    }

    protected void unassignRequest(ServletRequest request, ArgSet args,
        IRequest req, 
        IRequestQueue queue, IProfile profile, Locale locale)
        throws EProfileException {

        req.setRequestOwner("");
    }

    /**
     * Cancel request
     * <P>
     * 
     * (Certificate Request Processed - a manual "agent" profile based cert
     *  cancellation)
     * <P>
     * 
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a
     * certificate request has just been through the approval process
     * </ul>
     * @param request the servlet request
     * @param args argument set
     * @param req the certificate request
     * @param queue the certificate request queue
     * @param profile this profile
     * @param locale the system locale
     * @exception EProfileException an error related to this profile has
     * occurred
     */
    protected void cancelRequest(ServletRequest request, ArgSet args,
        IRequest req, 
        IRequestQueue queue, IProfile profile, Locale locale)
        throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);
        String auditInfoValue = auditInfoValue(req);

        // try {
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
        // } catch( EProfileException eAudit1 ) {
        //     // store a message in the signed audit log file
        //     auditMessage = CMS.getLogMessage(
        //                        LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
        //                        auditSubjectID,
        //                        ILogger.FAILURE,
        //                        auditRequesterID,
        //                        ILogger.SIGNED_AUDIT_CANCELLATION,
        //                        auditInfoValue );
        //
        //     audit( auditMessage );
        // }
    }

    /**
     * Reject request
     * <P>
     * 
     * (Certificate Request Processed - a manual "agent" profile based cert
     *  rejection)
     * <P>
     * 
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a
     * certificate request has just been through the approval process
     * </ul>
     * @param request the servlet request
     * @param args argument set
     * @param req the certificate request
     * @param queue the certificate request queue
     * @param profile this profile
     * @param locale the system locale
     * @exception EProfileException an error related to this profile has
     * occurred
     */
    protected void rejectRequest(ServletRequest request, ArgSet args,
        IRequest req, 
        IRequestQueue queue, IProfile profile, Locale locale) 
        throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);
        String auditInfoValue = auditInfoValue(req);

        // try {
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
        // } catch( EProfileException eAudit1 ) {
        //     // store a message in the signed audit log file
        //     auditMessage = CMS.getLogMessage(
        //                        LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
        //                        auditSubjectID,
        //                        ILogger.FAILURE,
        //                        auditRequesterID,
        //                        ILogger.SIGNED_AUDIT_REJECTION,
        //                        auditInfoValue );
        //
        //     audit( auditMessage );
        // }
    }

    /**
     * Approve request
     * <P>
     * 
     * (Certificate Request Processed - a manual "agent" profile based cert
     *  acceptance)
     * <P>
     * 
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a
     * certificate request has just been through the approval process
     * </ul>
     * @param request the servlet request
     * @param args argument set
     * @param req the certificate request
     * @param queue the certificate request queue
     * @param profile this profile
     * @param locale the system locale
     * @exception EProfileException an error related to this profile has
     * occurred
     */
    protected void approveRequest(ServletRequest request, ArgSet args, 
        IRequest req, 
        IRequestQueue queue, IProfile profile, Locale locale) 
        throws EProfileException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);

        try {
            profile.execute(req);
            req.setRequestStatus(RequestStatus.COMPLETE);

            ArgList outputlist = new ArgList();
            Enumeration outputIds = profile.getProfileOutputIds();

            if (outputIds != null) {
                while (outputIds.hasMoreElements()) {
                    String outputId = (String) outputIds.nextElement();
                    IProfileOutput profileOutput = profile.getProfileOutput(
                            outputId);

                    Enumeration outputNames = profileOutput.getValueNames();

                    if (outputNames != null) {
                        while (outputNames.hasMoreElements()) {
                            ArgSet outputset = new ArgSet();
                            String outputName = (String)
                                outputNames.nextElement();
                            IDescriptor outputDesc =
                                profileOutput.getValueDescriptor(locale,
                                    outputName);

                            if (outputDesc == null)
                                continue;
                            String outputSyntax = outputDesc.getSyntax();
                            String outputConstraint =
                                outputDesc.getConstraint();
                            String outputValueName =
                                outputDesc.getDescription(locale);
                            String outputValue = null;

                            try {
                                outputValue = profileOutput.getValue(
                                            outputName, 
                                            locale, req);
                            } catch (EProfileException e) {
                                CMS.debug("ProfileSubmitServlet: " +
                                    e.toString());
                            }

                            outputset.set(ARG_OUTPUT_ID, outputName);
                            outputset.set(ARG_OUTPUT_SYNTAX, outputSyntax);
                            outputset.set(ARG_OUTPUT_CONSTRAINT,
                                outputConstraint);
                            outputset.set(ARG_OUTPUT_NAME, outputValueName);
                            outputset.set(ARG_OUTPUT_VAL, outputValue);
                            outputlist.add(outputset);
                        }
                    }
                }
            }
            args.set(ARG_OUTPUT_LIST, outputlist);

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

            CMS.debug("ProfileProcessServlet: about to throw EProfileException because of bad profile execute.");
            throw new EProfileException(eAudit1.toString());

            
        }
    }

    protected void updateValues(ServletRequest request, IRequest req, 
        IRequestQueue queue, IProfile profile, Locale locale)
        throws ERejectException, EDeferException, EPropertyException {
        String profileSetId = req.getExtDataInString("profileSetId");

        Enumeration policies = profile.getProfilePolicies(profileSetId);
        int count = 0;

        while (policies.hasMoreElements()) {
            IProfilePolicy policy = (IProfilePolicy) policies.nextElement();

            setValue(locale, count, policy, req, request);
            count++;
        }

        policies = profile.getProfilePolicies(profileSetId);
        count = 0;
        while (policies.hasMoreElements()) {
            IProfilePolicy policy = (IProfilePolicy) policies.nextElement();

            validate(locale, count, policy, req, request);
            count++;
        }

    }

    protected void updateNotes(ServletRequest request, IRequest req) {
        String notes = request.getParameter(ARG_REQUEST_NOTES);

        if (notes != null) {
            req.setExtData("requestNotes", notes);
        }
    }

    protected void validate(Locale locale, int count, 
        IProfilePolicy policy, IRequest req, ServletRequest request) 
        throws ERejectException, EDeferException {
        IPolicyConstraint con = policy.getConstraint();

        con.validate(req);
    }

    protected void setValue(Locale locale, int count, 
        IProfilePolicy policy, IRequest req, ServletRequest request) 
        throws EPropertyException {
        // handle default policy
        IPolicyDefault def = policy.getDefault();
        Enumeration defNames = def.getValueNames();

        while (defNames.hasMoreElements()) {
            String defName = (String) defNames.nextElement();
            String defValue = request.getParameter(defName);

            def.setValue(defName, locale, req, defValue);
        }
    }

    /**
     * Signed Audit Log Requester ID
     *
     * This method is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return id string containing the signed audit log message RequesterID
     */
    private String auditRequesterID(IRequest request) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String requesterID = ILogger.UNIDENTIFIED;

        if (request != null) {
            // overwrite "requesterID" if and only if "id" != null
            String id = request.getRequestId().toString();

            if (id != null) {
                requesterID = id.trim();
            }
        }

        return requesterID;
    }

    /**
     * Signed Audit Log Info Value
     *
     * This method is called to obtain the "reason" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return reason string containing the signed audit log message reason
     */
    private String auditInfoValue(IRequest request) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String reason = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        if (request != null) {
            // overwrite "reason" if and only if "info" != null
            String info =
                request.getExtDataInString(SIGNED_AUDIT_CERT_REQUEST_REASON);

            if (info != null) {
                reason = info.trim();

                // overwrite "reason" if and only if "reason" is empty
                if (reason.equals("")) {
                    reason = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                }
            }
        }

        return reason;
    }

    /**
     * Signed Audit Log Info Certificate Value
     *
     * This method is called to obtain the certificate from the passed in
     * "X509CertImpl" for a signed audit log message.
     * <P>
     *
     * @param x509cert an X509CertImpl
     * @return cert string containing the certificate
     */
    private String auditInfoCertValue(X509CertImpl x509cert) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        if (x509cert == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        try {
            rawData = x509cert.getEncoded();
        } catch (CertificateEncodingException e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        String cert = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = com.netscape.osutil.OSUtil.BtoA(rawData).trim();

            // extract all line separators from the "base64Data"
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < base64Data.length(); i++) {
                  if (!Character.isWhitespace(base64Data.charAt(i))) {
                    sb.append(base64Data.charAt(i));
                }
            }
            cert = sb.toString();
        }

        if (cert != null) {
            cert = cert.trim();

            if (cert.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return cert;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
    }
}

