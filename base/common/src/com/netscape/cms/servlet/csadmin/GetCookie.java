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
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

public class GetCookie extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 2466968231929541707L;
    private String mErrorFormPath = null;
    private String mFormPath = null;

    private final static String LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE =
            "LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE_1";
    private final static String LOGGING_SIGNED_AUDIT_ROLE_ASSUME =
            "LOGGING_SIGNED_AUDIT_ROLE_ASSUME_3";

    public GetCookie() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CMS.debug("GetCookie init");
        mTemplates.remove(ICMSRequest.SUCCESS);
        mErrorFormPath = sc.getInitParameter("errorTemplatePath");
        if (mOutputTemplatePath != null) {
            mFormPath = mOutputTemplatePath;
        }
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMS.debug("GetCookie start");
        IAuthToken authToken = null;
        IConfigStore cs = CMS.getConfigStore();

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        String url = httpReq.getParameter("url");
        CMS.debug("GetCookie before auth, url =" + url);
        String url_e = "";
        URL u = null;
        try {
            url_e = URLDecoder.decode(url, "UTF-8");
            u = new URL(url_e);
        } catch (Exception eee) {
            throw new ECMSGWException(
                    "GetCookie missing parameter: url");
        }

        int index2 = url_e.indexOf("subsystem=");
        String subsystem = "";
        if (index2 > 0) {
            subsystem = url.substring(index2 + 10);
            int index1 = subsystem.indexOf("&");
            if (index1 > 0)
                subsystem = subsystem.substring(0, index1);
        }

        try {
            authToken = authenticate(cmsReq);
        } catch (Exception e) {
            CMS.debug("GetCookie authentication failed");
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "",
                            e.toString()));
            header.addStringValue("sd_uid", "");
            header.addStringValue("sd_pwd", "");
            header.addStringValue("host", u.getHost());
            header.addStringValue("sdhost", CMS.getEESSLHost());
            header.addStringValue("subsystem", subsystem);
            header.addStringValue("url", url_e);
            header.addStringValue("errorString", "Failed Authentication");
            String sdname = cs.getString("securitydomain.name", "");
            header.addStringValue("sdname", sdname);

            CMS.debug("mErrorFormPath=" + mErrorFormPath);
            try {
                form = getTemplate(mErrorFormPath, httpReq, locale);
            } catch (IOException eee) {
                CMS.debug("GetCookie process: cant locate the form");
                /*
                                log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
                                throw new ECMSGWException(
                                  CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
                */
            }

            if (form == null) {
                CMS.debug("GetCookie::process() - form is null!");
                throw new EBaseException("form is null");
            }

            try {
                ServletOutputStream out = httpResp.getOutputStream();

                cmsReq.setStatus(ICMSRequest.SUCCESS);
                httpResp.setContentType("text/html");
                form.renderOutput(out, argSet);
            } catch (IOException ee) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", ee.toString()));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
            }
            return;
        }

        if (authToken != null) {
            String uid = authToken.getInString("uid");

            String addr = "";
            try {
                addr = u.getHost();
            } catch (Exception e) {
            }

            try {
                SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(httpReq));

                InstallToken installToken = processor.getInstallToken(uid, addr, subsystem);
                String cookie = installToken.getToken();

                if (!url.startsWith("$")) {
                    try {
                        form = getTemplate(mFormPath, httpReq, locale);
                    } catch (IOException e) {
                        CMS.debug("GetCookie process: cant locate the form");
                        /*
                        log(ILogger.LL_FAILURE,
                          CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
                        throw new ECMSGWException(
                          CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
                        */
                    }

                    header.addStringValue("url", url);
                    header.addStringValue("session_id", cookie);

                    try {
                        ServletOutputStream out = httpResp.getOutputStream();

                        cmsReq.setStatus(ICMSRequest.SUCCESS);
                        httpResp.setContentType("text/html");
                        form.renderOutput(out, argSet);

                    } catch (IOException e) {
                        log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
                        throw new ECMSGWException(
                                CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Retrieves locale based on the request.
     */
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                    UserInfo.getUserCountry(lang));
        }
        return locale;
    }
}
