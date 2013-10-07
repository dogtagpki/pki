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
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IPolicyConstraint;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.cms.servlet.common.CMSRequest;

/**
 * This servlet allows reviewing of profile-based request.
 *
 * @version $Revision$, $Date$
 */
public class ProfileReviewServlet extends ProfileServlet {

    /**
     *
     */
    private static final long serialVersionUID = -6559751428547928511L;

    private static final String PROP_AUTHORITY_ID = "authorityId";

    private String mAuthorityId = null;
    ICertificateAuthority authority = null;
    private Random mRandom = null;

    public ProfileReviewServlet() {
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

        if (mAuthorityId != null)
            authority = (ICertificateAuthority) CMS.getSubsystem(mAuthorityId);

        if (authority != null && authority.noncesEnabled()) {
            mRandom = new Random();
        }
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param requestId the ID of the profile to review
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        CMS.debug("ProfileReviewServlet: start serving");

        Locale locale = getLocale(request);
        ArgSet args = new ArgSet();
        IAuthToken authToken = null;

        if (mAuthMgr != null) {
            try {
                authToken = authenticate(request);
            } catch (EBaseException e) {
                CMS.debug("ReviewReqServlet: " + e.toString());
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
                args.set(ARG_ERROR_CODE, "1");
                args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                        "CMS_AUTHENTICATION_ERROR"));
                outputTemplate(request, response, args);
                return;
            }
        }

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
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
            return;
        }

        // (1) Read request from the database

        // (2) Get profile id from the request
        if (mProfileSubId == null || mProfileSubId.equals("")) {
            mProfileSubId = IProfileSubsystem.ID;
        }
        CMS.debug("ProfileReviewServlet: SubId=" + mProfileSubId);
        IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem(mProfileSubId);

        if (ps == null) {
            CMS.debug("ProfileReviewServlet: ProfileSubsystem not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }

        // retrieve request

        if (authority == null) {
            CMS.debug("ProfileReviewServlet: Authority " + mAuthorityId +
                    " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }
        IRequestQueue queue = authority.getRequestQueue();

        if (queue == null) {
            CMS.debug("ProfileReviewServlet: Request Queue of " +
                    mAuthorityId + " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }

        String requestId = request.getParameter("requestId");
        IRequest req = null;

        CMS.debug("ProfileReviewServlet: requestId=" + requestId);
        try {
            req = queue.findRequest(new RequestId(requestId));
        } catch (EBaseException e) {
            // request not found
            CMS.debug("ProfileReviewServlet: request not found requestId=" +
                    requestId + " " + e.toString());
        }
        if (req == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_REQUEST_NOT_FOUND", requestId));
            outputTemplate(request, response, args);
            return;
        }

        String profileId = req.getExtDataInString("profileId");

        CMS.debug("ProfileReviewServlet: requestId=" +
                requestId + " profileId=" + profileId);
        IProfile profile = null;

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            // profile not found
            CMS.debug("ProfileReviewServlet: profile not found requestId=" +
                    requestId + " profileId=" + profileId + " " + e.toString());
        }
        if (profile == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
            outputTemplate(request, response, args);
            return;
        }

        String profileSetId = req.getExtDataInString("profileSetId");

        CMS.debug("ProfileReviewServlet: profileSetId=" + profileSetId);
        Enumeration<String> policyIds = (profileSetId != null && profileSetId.length() > 0) ?
                                 profile.getProfilePolicyIds(profileSetId) : null;
        ArgList list = new ArgList();

        if (policyIds != null) {
            while (policyIds.hasMoreElements()) {
                String id = policyIds.nextElement();
                IProfilePolicy policy =
                        profile.getProfilePolicy(req.getExtDataInString("profileSetId"),
                                id);

                // (3) query all the profile policies
                // (4) default plugins convert request parameters into string
                //     http parameters
                handlePolicy(list, response, locale,
                        id, policy, req);
            }
        }

        if (authority != null && authority.noncesEnabled()) {
            long n = mRandom.nextLong();
            Map<Object, Long> nonces = authority.getNonces(request, "cert-request");
            nonces.put(req.getRequestId().toBigInteger(), n);
            args.set(ARG_REQUEST_NONCE, Long.toString(n));
        }

        args.set(ARG_REQUEST_ID, req.getRequestId().toString());
        args.set(ARG_REQUEST_TYPE, req.getRequestType());
        args.set(ARG_REQUEST_STATUS, req.getRequestStatus().toString());
        if (req.getRequestOwner() == null) {
            args.set(ARG_REQUEST_OWNER, "");
        } else {
            args.set(ARG_REQUEST_OWNER, req.getRequestOwner());
        }
        args.set(ARG_REQUEST_CREATION_TIME, req.getCreationTime().toString());
        args.set(ARG_REQUEST_MODIFICATION_TIME,
                req.getModificationTime().toString());

        args.set(ARG_PROFILE_ID, profileId);
        args.set(ARG_PROFILE_APPROVED_BY,
                req.getExtDataInString("profileApprovedBy"));
        args.set(ARG_PROFILE_SET_ID, req.getExtDataInString("profileSetId"));
        if (profile.isVisible()) {
            args.set(ARG_PROFILE_IS_VISIBLE, "true");
        } else {
            args.set(ARG_PROFILE_IS_VISIBLE, "false");
        }
        args.set(ARG_PROFILE_NAME, profile.getName(locale));
        args.set(ARG_PROFILE_DESC, profile.getDescription(locale));
        args.set(ARG_PROFILE_REMOTE_HOST,
                req.getExtDataInString("profileRemoteHost"));
        args.set(ARG_PROFILE_REMOTE_ADDR,
                req.getExtDataInString("profileRemoteAddr"));
        if (req.getExtDataInString("requestNotes") == null) {
            args.set(ARG_REQUEST_NOTES, "");
        } else {
            args.set(ARG_REQUEST_NOTES,
                    req.getExtDataInString("requestNotes"));
        }

        args.set(ARG_RECORD, list);
        args.set(ARG_ERROR_CODE, "0");
        args.set(ARG_ERROR_REASON, "");

        ArgList inputlist = new ArgList();

        // populate authentication parameters

        // populate input parameters
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);

                Enumeration<String> inputNames = profileInput.getValueNames();

                if (inputNames != null) {
                    while (inputNames.hasMoreElements()) {
                        ArgSet inputset = new ArgSet();
                        String inputName = inputNames.nextElement();

                        IDescriptor inputDesc = profileInput.getValueDescriptor(locale, inputName);

                        if (inputDesc == null)
                            continue;
                        String inputSyntax = inputDesc.getSyntax();
                        String inputConstraint = inputDesc.getConstraint();
                        String inputValueName = inputDesc.getDescription(locale);
                        String inputValue = null;

                        try {
                            inputValue = profileInput.getValue(inputName, locale, req);
                        } catch (EBaseException e) {
                            CMS.debug("ProfileReviewServlet: " + e.toString());
                        }

                        inputset.set(ARG_INPUT_ID, inputName);
                        inputset.set(ARG_INPUT_SYNTAX, inputSyntax);
                        inputset.set(ARG_INPUT_CONSTRAINT, inputConstraint);
                        inputset.set(ARG_INPUT_NAME, inputValueName);
                        inputset.set(ARG_INPUT_VAL, inputValue);
                        inputlist.add(inputset);
                    }
                }
            }
        }
        args.set(ARG_INPUT_LIST, inputlist);

        // if request in complete state

        ArgList outputlist = new ArgList();
        Enumeration<String> outputIds = profile.getProfileOutputIds();

        if (outputIds != null) {
            while (outputIds.hasMoreElements()) {
                String outputId = outputIds.nextElement();
                IProfileOutput profileOutput = profile.getProfileOutput(outputId
                        );

                Enumeration<String> outputNames = profileOutput.getValueNames();

                if (outputNames != null) {
                    while (outputNames.hasMoreElements()) {
                        ArgSet outputset = new ArgSet();
                        String outputName = outputNames.nextElement
                                ();
                        IDescriptor outputDesc =
                                profileOutput.getValueDescriptor(locale, outputName);

                        if (outputDesc == null)
                            continue;
                        String outputSyntax = outputDesc.getSyntax();
                        String outputConstraint = outputDesc.getConstraint();
                        String outputValueName = outputDesc.getDescription(locale);
                        String outputValue = null;

                        try {
                            outputValue = profileOutput.getValue(outputName,
                                        locale, req);
                        } catch (EProfileException e) {
                            CMS.debug("ProfileSubmitServlet: " + e.toString(
                                    ));
                        }

                        outputset.set(ARG_OUTPUT_ID, outputName);
                        outputset.set(ARG_OUTPUT_SYNTAX, outputSyntax);
                        outputset.set(ARG_OUTPUT_CONSTRAINT, outputConstraint);
                        outputset.set(ARG_OUTPUT_NAME, outputValueName);
                        outputset.set(ARG_OUTPUT_VAL, outputValue);
                        outputlist.add(outputset);
                    }
                }
            }
        }
        args.set(ARG_OUTPUT_LIST, outputlist);

        // (5) return info as template
        outputTemplate(request, response, args);
    }

    private void handlePolicy(ArgList list, ServletResponse response,
            Locale locale, String id, IProfilePolicy policy,
            IRequest req) {
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

                if (defDesc == null)
                    continue;
                String defSyntax = defDesc.getSyntax();
                String defConstraint = defDesc.getConstraint();
                String defValueName = defDesc.getDescription(locale);
                String defValue = null;

                try {
                    defValue = def.getValue(defName, locale, req);
                } catch (EPropertyException ee) {
                    CMS.debug("ProfileReviewServlet: " + ee.toString());
                }

                defset.set(ARG_DEF_ID, defName);
                defset.set(ARG_DEF_SYNTAX, defSyntax);
                defset.set(ARG_DEF_CONSTRAINT, defConstraint);
                defset.set(ARG_DEF_NAME, defValueName);
                defset.set(ARG_DEF_VAL, defValue);
                deflist.add(defset);
            }
        }
        set.set(ARG_DEF_LIST, deflist);

        // handle constraint policy
        IPolicyConstraint con = policy.getConstraint();

        if (con != null) {
            String conDesc = con.getText(locale);

            set.set(ARG_CON_DESC, conDesc);
        }

        list.add(set);
    }
}
