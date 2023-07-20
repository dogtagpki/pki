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
package com.netscape.cms.servlet.connector;

import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;

/**
 * CA connector servlet
 * process requests from remote authority -
 * service request or return status.
 */
@WebServlet(
        name = "caConnector",
        urlPatterns = "/ca/connector",
        initParams = {
                @WebInitParam(name="GetClientCert",  value="true"),
                @WebInitParam(name="AuthzMgr",       value="BasicAclAuthz"),
                @WebInitParam(name="authority",      value="ca"),
                @WebInitParam(name="ID",             value="caConnector"),
                @WebInitParam(name="RequestEncoder", value="com.netscape.cmscore.connector.HttpRequestEncoder"),
                @WebInitParam(name="resourceID",     value="certServer.ca.connector"),
                @WebInitParam(name="interface",      value="agent"),
                @WebInitParam(name="AuthMgr",        value="certUserDBAuthMgr")
        }
)
public class CAConnectorServlet extends ConnectorServlet {

    private static final long serialVersionUID = 1L;

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAConnectorServlet.class);

    @Override
    public void normalizeProfileRequest(Request request) {

        super.normalizeProfileRequest(request);

        CAEngine engine = CAEngine.getInstance();
        ProfileSubsystem ps = engine.getProfileSubsystem();

        String profileId = request.getExtDataInString(Request.PROFILE_ID);
        EnrollProfile profile = null;

        try {
            logger.info("CAConnectorServlet: Updating profile " + profileId);

            profile = (EnrollProfile) ps.getProfile(profileId);
            profile.setDefaultCertInfo(request);

        } catch (EProfileException e) {
            logger.warn("Unable to update profile: " + e.getMessage(), e);
        }

        if (profile == null) {
            logger.error("Profile not found: " + profileId);
        }
    }
}
