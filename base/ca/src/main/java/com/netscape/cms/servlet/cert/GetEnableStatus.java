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
package com.netscape.cms.servlet.cert;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;

/**
 * Servlet to get the enrollment status, enable or disable.
 *
 * @version $Revision$, $Date$
 */
public class GetEnableStatus extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 3879769989681379834L;
    private final static String TPL_FILE = "userEnroll.template";
    private String mFormPath = null;

    public GetEnableStatus() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // coming from agent
        mFormPath = "/ca/" + TPL_FILE;

        mTemplates.remove(CMSRequest.SUCCESS);
    }

    @Override
    protected CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig configStore = engine.getConfig();

        AuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String reqHost = httpReq.getRemoteHost();

        logger.error(CMS.getLogMessage("CMSGW_CA_FROM_RA_NOT_IMP"));
        cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_NOT_YET_IMPLEMENTED")));
        cmsReq.setStatus(CMSRequest.ERROR);
        return;
    }

}
