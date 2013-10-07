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
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfilePolicy;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.cms.servlet.common.CMSRequest;

/**
 * Retrieve detailed information of a particular profile.
 *
 * @version $Revision$, $Date$
 */
public class ProfileSelectServlet extends ProfileServlet {

    /**
     *
     */
    private static final long serialVersionUID = -3765390650830903602L;
    private static final String PROP_AUTHORITY_ID = "authorityId";
    private String mAuthorityId = null;

    public ProfileSelectServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mAuthorityId = sc.getInitParameter(PROP_AUTHORITY_ID);
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param profileId the id of the profile to select
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        CMS.debug("ProfileSelectServlet: start serving");

        Locale locale = getLocale(request);

        IAuthToken authToken = null;
        ArgSet args = new ArgSet();

        if (mAuthMgr != null) {
            try {
                authToken = authenticate(request);
            } catch (EBaseException e) {
                CMS.debug("ProcessReqServlet: " + e.toString());
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
        CMS.debug("ProfileSelectServlet: SubId=" + mProfileSubId);
        IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem(mProfileSubId);

        if (ps == null) {
            CMS.debug("ProfileSelectServlet: ProfileSubsystem not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }

        // retrieve request
        IAuthority authority = (IAuthority) CMS.getSubsystem(mAuthorityId);

        if (authority == null) {
            CMS.debug("ProfileSelectServlet: Authority " + mAuthorityId +
                    " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }
        IRequestQueue queue = authority.getRequestQueue();

        if (queue == null) {
            CMS.debug("ProfileSelectServlet: Request Queue of " +
                    mAuthorityId + " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }

        IProfile profile = null;

        String profileId = request.getParameter("profileId");

        CMS.debug("ProfileSelectServlet: profileId=" + profileId);

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            // profile not found
            CMS.debug("ProfileSelectServlet: profile not found profileId=" +
                    profileId + " " + e.toString());
        }
        if (profile == null) {
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_PROFILE_NOT_FOUND", profileId));
            outputTemplate(request, response, args);
            return;
        }

        ArgList setlist = new ArgList();
        Enumeration<String> policySetIds = profile.getProfilePolicySetIds();

        if (policySetIds != null) {
            while (policySetIds.hasMoreElements()) {
                String setId = policySetIds.nextElement();

                ArgList list = new ArgList();
                Enumeration<String> policyIds = profile.getProfilePolicyIds(setId);

                if (policyIds != null) {
                    while (policyIds.hasMoreElements()) {
                        String id = policyIds.nextElement();
                        IProfilePolicy policy = profile.getProfilePolicy(setId, id);

                        // (3) query all the profile policies
                        // (4) default plugins convert request parameters into string
                        //     http parameters
                        handlePolicy(list, response, locale,
                                id, policy);
                    }
                }
                ArgSet setArg = new ArgSet();

                setArg.set(ARG_POLICY_SET_ID, setId);
                setArg.set(ARG_POLICY, list);
                setlist.add(setArg);
            }
        }
        args.set(ARG_POLICY_SET_LIST, setlist);

        args.set(ARG_PROFILE_ID, profileId);
        args.set(ARG_PROFILE_IS_ENABLED,
                Boolean.toString(ps.isProfileEnable(profileId)));
        args.set(ARG_PROFILE_ENABLED_BY, ps.getProfileEnableBy(profileId));
        args.set(ARG_PROFILE_NAME, profile.getName(locale));
        args.set(ARG_PROFILE_DESC, profile.getDescription(locale));
        args.set(ARG_PROFILE_IS_VISIBLE,
                Boolean.toString(profile.isVisible()));
        args.set(ARG_ERROR_CODE, "0");
        args.set(ARG_ERROR_REASON, "");

        try {
            boolean keyArchivalEnabled = CMS.getConfigStore().getBoolean("ca.connector.KRA.enable", false);
            if (keyArchivalEnabled == true) {
                CMS.debug("ProfileSelectServlet: keyArchivalEnabled is true");

                // output transport certificate if present
                args.set("transportCert",
                        CMS.getConfigStore().getString("ca.connector.KRA.transportCert", ""));
            } else {
                CMS.debug("ProfileSelectServlet: keyArchivalEnabled is false");
                args.set("transportCert", "");
            }
        } catch (EBaseException e) {
            CMS.debug("ProfileSelectServlet: exception caught:" + e.toString());
        }

        // build authentication
        ArgList authlist = new ArgList();
        IProfileAuthenticator authenticator = null;

        try {
            authenticator = profile.getAuthenticator();
        } catch (EProfileException e) {
            // authenticator not installed correctly
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_AUTHENTICATION_MANAGER_NOT_FOUND",
                    profile.getAuthenticatorId()));
            outputTemplate(request, response, args);
            return;
        }

        if (authenticator != null) {
            Enumeration<String> authNames = authenticator.getValueNames();

            if (authNames != null) {
                while (authNames.hasMoreElements()) {
                    ArgSet authset = new ArgSet();
                    String authName = authNames.nextElement();
                    IDescriptor authDesc =
                            authenticator.getValueDescriptor(locale, authName);

                    if (authDesc == null)
                        continue;
                    String authSyntax = authDesc.getSyntax();
                    String authConstraint = authDesc.getConstraint();
                    String authValueName = authDesc.getDescription(locale);

                    authset.set(ARG_AUTH_ID, authName);
                    authset.set(ARG_AUTH_SYNTAX, authSyntax);
                    authset.set(ARG_AUTH_CONSTRAINT, authConstraint);
                    authset.set(ARG_AUTH_NAME, authValueName);
                    authlist.add(authset);
                }
            }
            args.set(ARG_AUTH_LIST, authlist);
            args.set(ARG_AUTH_NAME, authenticator.getName(locale));
            args.set(ARG_AUTH_DESC, authenticator.getText(locale));
            args.set(ARG_AUTH_IS_SSL,
                    Boolean.toString(authenticator.isSSLClientRequired()));
        }

        // build input list
        ArgList inputlist = new ArgList();
        ArgList inputPluginlist = new ArgList();
        Enumeration<String> inputIds = profile.getProfileInputIds();

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);

                if (profileInput != null) {

                    ArgSet inputpluginset = new ArgSet();
                    inputpluginset.set(ARG_INPUT_PLUGIN_ID, inputId);
                    inputpluginset.set(ARG_INPUT_PLUGIN_NAME,
                            profileInput.getName(locale));
                    inputpluginset.set(ARG_INPUT_PLUGIN_DESC,
                            profileInput.getText(locale));
                    inputPluginlist.add(inputpluginset);

                    Enumeration<String> inputNames = profileInput.getValueNames();

                    if (inputNames != null) {
                        while (inputNames.hasMoreElements()) {
                            ArgSet inputset = new ArgSet();
                            String inputName = inputNames.nextElement();
                            IDescriptor inputDesc = profileInput.getValueDescriptor(
                                    locale, inputName);

                            if (inputDesc == null)
                                continue;
                            String inputSyntax = inputDesc.getSyntax();
                            String inputConstraint = inputDesc.getConstraint();
                            String inputValueName = inputDesc.getDescription(locale);
                            String inputValue = null;

                            inputset.set(ARG_INPUT_PLUGIN_ID, inputId);
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
        }
        args.set(ARG_INPUT_LIST, inputlist);
        args.set(ARG_INPUT_PLUGIN_LIST, inputPluginlist);
        args.set(ARG_IS_RENEWAL, profile.isRenewal());
        args.set(ARG_XML_OUTPUT, profile.isXmlOutput());

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

                if (defDesc == null)
                    continue;
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
        set.set(ARG_DEF_LIST, deflist);

        // handle constraint policy
        IPolicyConstraint con = policy.getConstraint();
        String conDesc = con.getText(locale);

        set.set(ARG_CON_DESC, conDesc);
        ArgList conlist = new ArgList();
        Enumeration<String> conNames = con.getConfigNames();
        if (conNames != null) {
            while (conNames.hasMoreElements()) {
                ArgSet conset = new ArgSet();
                String conName = conNames.nextElement();
                conset.set(ARG_CON_NAME, conName);
                conset.set(ARG_CON_VALUE, con.getConfig(conName));
                conlist.add(conset);
            }
        }
        set.set(ARG_CON_LIST, conlist);

        list.add(set);
    }

}
