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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.profile.ProfileSubsystem;

/**
 * List all enabled profiles.
 *
 * @version $Revision$, $Date$
 */
public class ProfileListServlet extends ProfileServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileListServlet.class);

    private static final long serialVersionUID = -5118812083812548395L;

    public ProfileListServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "ImportCert.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        logger.debug("ProfileListServlet: start serving");

        CAEngine engine = CAEngine.getInstance();
        Locale locale = getLocale(request);

        ArgSet args = new ArgSet();
        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "list");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
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
            mProfileSubId = ProfileSubsystem.ID;
        }
        logger.debug("ProfileListServlet: SubId=" + mProfileSubId);
        ProfileSubsystem ps = engine.getProfileSubsystem(mProfileSubId);

        if (ps == null) {
            logger.warn("ProfileListServlet: ProfileSubsystem " +
                    mProfileSubId + " not found");
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, CMS.getUserMessage(locale,
                    "CMS_INTERNAL_ERROR"));
            outputTemplate(request, response, args);
            return;
        }

        ArgList list = new ArgList();
        Enumeration<String> e = ps.getProfileIds();

        if (e != null) {
            while (e.hasMoreElements()) {
                String id = e.nextElement();
                Profile profile = null;

                try {
                    profile = ps.getProfile(id);
                } catch (EBaseException e1) {
                    // skip bad profile
                    logger.warn("ProfileListServlet: profile " + id +
                            " not found (skipped) " + e1.getMessage(), e);
                    continue;
                }

                if (profile == null) {
                    logger.warn("ProfileListServlet: profile " + id +
                            " not found (skipped)");
                    continue;
                }

                String name = profile.getName(locale);
                String desc = profile.getDescription(locale);

                ArgSet profileArgs = new ArgSet();

                profileArgs.set(ARG_PROFILE_IS_ENABLED,
                        Boolean.toString(ps.isProfileEnable(id)));
                profileArgs.set(ARG_PROFILE_ENABLED_BY,
                        ps.getProfileEnableBy(id));
                profileArgs.set(ARG_PROFILE_ID, id);
                profileArgs.set(ARG_PROFILE_IS_VISIBLE,
                        Boolean.toString(profile.isVisible()));
                profileArgs.set(ARG_PROFILE_NAME, name);
                profileArgs.set(ARG_PROFILE_DESC, desc);
                list.add(profileArgs);

            }
        }
        args.set(ARG_RECORD, list);
        args.set(ARG_ERROR_CODE, "0");
        args.set(ARG_ERROR_REASON, "");

        // (5) return info as template
        outputTemplate(request, response, args);
    }

}
