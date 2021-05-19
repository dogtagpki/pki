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
import java.util.Date;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
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
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;

/**
 * Servlet to report the status, ie, the agent-initiated user
 * enrollment is enabled or disabled.
 *
 * @version $Revision$, $Date$
 */
public class DisplayHashUserEnroll extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -7063912475278810362L;
    private final static String TPL_FILE = "/ra/hashDirUserEnroll.template";
    private final static String TPL_ERROR_FILE = "/ra/GenErrorHashDirEnroll.template";
    private String mFormPath = null;

    public DisplayHashUserEnroll() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        try {
            mFormPath = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (mFormPath == null)
                mFormPath = TPL_FILE;
        } catch (Exception e) {
        }

        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    @Override
    protected CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * Services the request
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig configStore = engine.getConfig();

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
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_ERR_GET_TEMPLATE"));
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_NOT_YET_IMPLEMENTED")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        String val = configStore.getString("hashDirEnrollment.name");
        AuthSubsystem authSS = engine.getAuthSubsystem();
        AuthManager authMgr = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr;
        boolean isEnable = mgr.isEnable(reqHost);

        if (!isEnable) {
            printError(cmsReq, "0");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }

        Date date = new Date();
        long currTime = date.getTime();
        long timeout = mgr.getTimeout(reqHost);
        long lastlogin = mgr.getLastLogin(reqHost);
        long diff = currTime - lastlogin;

        if (lastlogin == 0)
            mgr.setLastLogin(reqHost, currTime);
        else if (diff > timeout) {
            mgr.disable(reqHost);
            printError(cmsReq, "2");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }

        mgr.setLastLogin(reqHost, currTime);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
        return;
    }

    private void printError(CMSRequest cmsReq, String errorCode)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        mTemplates.remove(ICMSRequest.SUCCESS);
        header.addStringValue("authority", "Registration Manager");
        header.addStringValue("errorCode", errorCode);
        String formPath = TPL_ERROR_FILE;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(formPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_ERR_GET_TEMPLATE", formPath, e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
    }
}
