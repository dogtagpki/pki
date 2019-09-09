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

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.cms.authentication.HashAuthentication;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ArgBlock;

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
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // coming from agent
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        mTemplates.remove(ICMSRequest.SUCCESS);
    }

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
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMSEngine engine = CMS.getCMSEngine();
        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        String reqHost = httpReq.getRemoteHost();

        if (!(mAuthority instanceof IRegistrationAuthority)) {
            logger.error(CMS.getLogMessage("CMSGW_CA_FROM_RA_NOT_IMP"));
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_NOT_YET_IMPLEMENTED")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();

        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        IConfigStore configStore = engine.getConfigStore();
        String val = configStore.getString("hashDirEnrollment.name");
        IAuthSubsystem authSS = (IAuthSubsystem) engine.getSubsystem(IAuthSubsystem.ID);
        IAuthManager authMgr = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr;
        long timeout = HashAuthentication.DEFAULT_TIMEOUT / 1000;

        header.addStringValue("timeout", "" + timeout);
        header.addStringValue("reqHost", reqHost);

        for (Enumeration<String> hosts = mgr.getHosts(); hosts.hasMoreElements();) {
            ArgBlock rarg = new ArgBlock();

            rarg.addStringValue("hosts", hosts.nextElement());
            argSet.addRepeatRecord(rarg);
        }

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
        return;
    }

}
