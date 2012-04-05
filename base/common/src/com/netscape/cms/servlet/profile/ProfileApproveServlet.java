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

import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.cms.servlet.common.CMSRequest;

/**
 * Toggle the approval state of a profile
 *
 * @version $Revision$, $Date$
 */
public class ProfileApproveServlet extends ProfileServlet {

    /**
     *
     */
    private static final long serialVersionUID = 3956879326742839550L;
    private static final String PROP_AUTHORITY_ID = "authorityId";
    private String mAuthorityId = null;

    private final static String LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL =
            "LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL_4";
    private final static String OP_APPROVE = "approve";
    private final static String OP_DISAPPROVE = "disapprove";

    public ProfileApproveServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "ImportCert.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mAuthorityId = sc.getInitParameter(PROP_AUTHORITY_ID);
    }

    /**
     * Process the HTTP request.
     * <P>
     *
     * <ul>
     * <li>http.param profileId the id of the profile to change
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL used when an agent approves/disapproves a cert
     * profile set by the administrator for automatic approval
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     * @exception EBaseException an error has occurred
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditProfileID = auditProfileID(request);
        String auditProfileOp = auditProfileOp(request);

        String userid = null;
        IAuthToken authToken = null;
        ArgSet args = new ArgSet();

        Locale locale = getLocale(request);

        IProfile profile = null;

        String profileId = null;

        IProfileSubsystem ps = null;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            try {
                authToken = authenticate(cmsReq);
                auditSubjectID = auditSubjectID();
                CMS.debug("uid=" + authToken.getInString("userid"));
                userid = authToken.getInString("userid");
            } catch (Exception e) {
                auditSubjectID = auditSubjectID();
                CMS.debug(e.toString());
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE",
                                e.toString()));
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_AUTHENTICATION_ERROR"));
                outputTemplate(request, response, args);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);

                return;
            }

            AuthzToken authzToken = null;

            try {
                authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "approve");
            } catch (EAuthzAccessDenied e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE",
                                e.toString()));
            } catch (Exception e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE",
                                e.toString()));
            }

            if (authzToken == null) {
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_AUTHORIZATION_ERROR"));
                outputTemplate(request, response, args);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);

                return;
            }

            CMS.debug("ProfileApproveServlet: start serving");
            // (1) Read request from the database

            // (2) Get profile id from the request
            if (mProfileSubId == null || mProfileSubId.equals("")) {
                mProfileSubId = IProfileSubsystem.ID;
            }
            CMS.debug("ProfileApproveServlet: SubId=" + mProfileSubId);
            ps = (IProfileSubsystem) CMS.getSubsystem(mProfileSubId);

            if (ps == null) {
                CMS.debug("ProfileApproveServlet: ProfileSubsystem not found");
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);

                return;
            }

            // retrieve request
            IAuthority authority = (IAuthority) CMS.getSubsystem(mAuthorityId);

            if (authority == null) {
                CMS.debug("ProfileApproveServlet: Authority " + mAuthorityId +
                        " not found");
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);

                return;
            }
            IRequestQueue queue = authority.getRequestQueue();

            if (queue == null) {
                CMS.debug("ProfileApproveServlet: Request Queue of " +
                        mAuthorityId + " not found");
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);

                return;
            }

            profileId = request.getParameter("profileId");

            CMS.debug("ProfileApproveServlet: profileId=" + profileId);

            args.set(ARG_ERROR_CODE, "0");
            args.set(ARG_ERROR_REASON, "");

            try {
                if (ps.isProfileEnable(profileId)) {
                    if (ps.checkOwner()) {
                        if (ps.getProfileEnableBy(profileId).equals(userid)) {
                            ps.disableProfile(profileId);
                        } else {
                            // only enableBy can disable profile
                            args.set(ARG_ERROR_CODE, "1");
                            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                                    "CMS_PROFILE_NOT_OWNER"));
                            outputTemplate(request, response, args);

                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditProfileID,
                                    auditProfileOp);

                            audit(auditMessage);

                            return;
                        }
                    } else {
                        ps.disableProfile(profileId);
                    }
                } else {
                    ps.enableProfile(profileId, userid);
                }

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);
            } catch (EProfileException e) {
                // profile not enabled
                CMS.debug("ProfileApproveServlet: profile not error " +
                        e.toString());
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_INTERNAL_ERROR"));
                outputTemplate(request, response, args);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProfileID,
                            auditProfileOp);

                audit(auditMessage);

                return;
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditProfileID,
                        auditProfileOp);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
            // } catch( ServletException eAudit2 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditProfileID,
            //                        auditProfileOp );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit2;
        }

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            // profile not found
            CMS.debug("ProfileApproveServlet: profile not found " +
                    e.toString());
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, e.toString());
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
            outputTemplate(request, response, args);
            return;
        }
        if (profile == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
            outputTemplate(request, response, args);
            return;
        }

        Enumeration<String> policySetIds = profile.getProfilePolicySetIds();

        ArgList setlist = new ArgList();

        while (policySetIds.hasMoreElements()) {
            String setId = policySetIds.nextElement();

            Enumeration<String> policyIds = profile.getProfilePolicyIds(setId);
            ArgList list = new ArgList();

            while (policyIds.hasMoreElements()) {
                String id = policyIds.nextElement();
                IProfilePolicy policy = profile.getProfilePolicy(setId, id);

                // (3) query all the profile policies
                // (4) default plugins convert request parameters
                //     into string http parameters
                handlePolicy(list, response, locale,
                        id, policy);
            }
            ArgSet setArg = new ArgSet();

            setArg.set(ARG_POLICY_SET_ID, setId);
            setArg.set(ARG_POLICY, list);
            setlist.add(setArg);
        }
        args.set(ARG_POLICY_SET_LIST, setlist);

        args.set(ARG_PROFILE_ID, profileId);
        args.set(ARG_PROFILE_IS_ENABLED,
                Boolean.toString(ps.isProfileEnable(profileId)));
        args.set(ARG_PROFILE_ENABLED_BY, ps.getProfileEnableBy(profileId));
        args.set(ARG_PROFILE_NAME, profile.getName(locale));
        args.set(ARG_PROFILE_DESC, profile.getDescription(locale));

        // (5) return info as template
        outputTemplate(request, response, args);
    }

    private void handlePolicy(ArgList list, ServletResponse response,
            Locale locale, String id, IProfilePolicy policy) {
        ArgSet set = new ArgSet();

        set.set(ARG_POLICY_ID, id);

        // handle default policy
        IPolicyDefault def = policy.getDefault();
        String dDesc = def.getText(locale);

        set.set(ARG_DEF_DESC, dDesc);

        ArgList deflist = new ArgList();
        Enumeration<String> defNames = def.getValueNames();

        if (defNames != null) {
            while (defNames.hasMoreElements()) {
                ArgSet defset = new ArgSet();
                String defName = defNames.nextElement();
                IDescriptor defDesc = def.getValueDescriptor(locale, defName);
                if (defDesc == null) {
                    CMS.debug("defName=" + defName);
                } else {
                    String defSyntax = defDesc.getSyntax();
                    String defConstraint = defDesc.getConstraint();
                    String defValueName = defDesc.getDescription(locale);
                    String defValue = null;

                    defset.set(ARG_DEF_ID, defName);
                    defset.set(ARG_DEF_SYNTAX, defSyntax);
                    defset.set(ARG_DEF_CONSTRAINT, defConstraint);
                    defset.set(ARG_DEF_NAME, defValueName);
                    defset.set(ARG_DEF_VAL, defValue);
                    deflist.add(defset);
                }
            }
        }
        set.set(ARG_DEF_LIST, deflist);

        // handle constraint policy
        IPolicyConstraint con = policy.getConstraint();
        String conDesc = con.getText(locale);

        set.set(ARG_CON_DESC, conDesc);

        list.add(set);
    }

    /**
     * Signed Audit Log Profile ID
     *
     * This method is called to obtain the "ProfileID" for
     * a signed audit log message.
     * <P>
     *
     * @param req HTTP request
     * @return id string containing the signed audit log message ProfileID
     */
    private String auditProfileID(HttpServletRequest req) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String profileID = null;

        // Obtain the profileID
        profileID = req.getParameter("profileId");

        if (profileID != null) {
            profileID = profileID.trim();
        } else {
            profileID = ILogger.UNIDENTIFIED;
        }

        return profileID;
    }

    /**
     * Signed Audit Log Profile Operation
     *
     * This method is called to obtain the "Profile Operation" for
     * a signed audit log message.
     * <P>
     *
     * @param req HTTP request
     * @return operation string containing either OP_APPROVE, OP_DISAPPROVE,
     *         or SIGNED_AUDIT_EMPTY_VALUE
     */
    private String auditProfileOp(HttpServletRequest req) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        if (mProfileSubId == null ||
                mProfileSubId.equals("")) {
            mProfileSubId = IProfileSubsystem.ID;
        }

        IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem(mProfileSubId);

        if (ps == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        String profileID = auditProfileID(req);

        if (profileID == ILogger.UNIDENTIFIED) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        if (ps.isProfileEnable(profileID)) {
            return OP_DISAPPROVE;
        } else {
            return OP_APPROVE;
        }
    }
}
