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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.cms.authentication.HashAuthentication;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * 'Face-to-face' certificate enrollment.
 *
 * @version $Revision$, $Date$
 */
public class DirAuthServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 3906057586972768401L;
    private final static String TPL_FILE = "/ra/hashEnrollmentSubmit.template";
    private final static String TPL_ERROR_FILE = "/ra/GenErrorHashDirEnroll.template";
    private String mFormPath = null;

    public DirAuthServlet() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
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

    /**
     * Process the HTTP request. This servlet reads configuration information
     * from the hashDirEnrollment configuration substore
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        String reqHost = httpReq.getRemoteHost();

        // Construct an ArgBlock
        IArgBlock args = cmsReq.getHttpParams();

        if (!(mAuthority instanceof IRegistrationAuthority)) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_CA_FROM_RA_NOT_IMP"));
            cmsReq.setError(new ECMSGWException(
                    CMS.getLogMessage("CMSGW_NOT_YET_IMPLEMENTED")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, httpReq, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
            cmsReq.setError(new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();

        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);
        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "submit");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        IConfigStore configStore = CMS.getConfigStore();
        String val = configStore.getString("hashDirEnrollment.name");
        IAuthSubsystem authSS = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
        IAuthManager authMgr = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr;

        Date date = new Date();
        long currTime = date.getTime();
        long timeout = mgr.getTimeout(reqHost);
        long lastlogin = mgr.getLastLogin(reqHost);
        long diff = currTime - lastlogin;

        boolean enable = mgr.isEnable(reqHost);

        if (!enable) {
            printError(cmsReq, "0");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }
        if (lastlogin == 0)
            mgr.setLastLogin(reqHost, currTime);
        else if (diff > timeout) {
            mgr.disable(reqHost);
            printError(cmsReq, "2");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }

        mgr.setLastLogin(reqHost, currTime);

        String uid = args.getValueAsString("uid");
        long pageid = mgr.getPageID();
        String pageID = pageid + "";

        mgr.addAuthToken(pageID, authToken);

        header.addStringValue("pageID", pageID);
        header.addStringValue("uid", uid);
        header.addStringValue("fingerprint", mgr.hashFingerprint(reqHost, pageID, uid));
        header.addStringValue("hostname", reqHost);

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_ERR_STREAM_TEMPLATE", e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE")));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
        return;
    }

    private void printError(CMSRequest cmsReq, String errorCode)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
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
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_ERR_GET_TEMPLATE", formPath, e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_ERR_STREAM_TEMPLATE", e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE")));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
    }

}
