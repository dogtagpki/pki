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

import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import java.math.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;
import com.netscape.cms.servlet.*;
import com.netscape.cmsutil.xml.*;
import org.w3c.dom.*;


public class GetCookie extends CMSServlet {

    private final static String SUCCESS = "0";
    private final static String FAILED = "1";
    private static Random mRandom = null;
    private final static int SESSION_MAX_AGE = 3600;
    private String mErrorFormPath = null;
    private String mFormPath = null;

    public GetCookie() {
        super();
    }

    /**
     * initialize the servlet.
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CMS.debug("GetCookie init");
        mTemplates.remove(CMSRequest.SUCCESS);
        mRandom = new Random();
        mErrorFormPath = sc.getInitParameter("errorTemplatePath");
        if (mOutputTemplatePath != null) {
          mFormPath = mOutputTemplatePath;
        }
    }

    /**
     * Process the HTTP request. 
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMS.debug("GetCookie start");
        IAuthToken authToken = null;
        int sessionMaxAge = SESSION_MAX_AGE;
        IConfigStore cs = CMS.getConfigStore();
        try {
            sessionMaxAge = cs.getInteger("sessionMaxAge", SESSION_MAX_AGE);
        } catch (Exception e) {
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock(); 
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        String url = httpReq.getParameter("url");
        CMS.debug("GetCookie before auth, url ="+url);
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
            subsystem = url.substring(index2+10);
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
            String sdname = cs.getString("preop.securitydomain.name", "");
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

            if( form == null ) {
                CMS.debug("GetCookie::process() - form is null!");
                throw new EBaseException( "form is null" );
            }

            try {
                ServletOutputStream out = httpResp.getOutputStream();

                cmsReq.setStatus(CMSRequest.SUCCESS);
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

        String cookie = "";
        if (authToken != null) {
            String uid = authToken.getInString("uid");
            String groupname = getGroupName(uid, subsystem);

            if (groupname != null) {
                // assign cookie
                long num = mRandom.nextLong();
                cookie = num+"";
                ISecurityDomainSessionTable ctable = CMS.getSecurityDomainSessionTable();
                String addr = "";
                try {
                    addr = u.getHost();
                } catch (Exception e) {
                }
                String ip = "";
                try {
                    ip = InetAddress.getByName(addr).toString();
                    int index = ip.indexOf("/");
                    if (index > 0)
                        ip = ip.substring(index+1);
                } catch (Exception e) {
                }

                ctable.addEntry(cookie, ip, uid, groupname);
                try {
                    String sd_url = "https://"+CMS.getEESSLHost()+":"+CMS.getEESSLPort();
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

                        EBaseException error = null;
                        try {
                            ServletOutputStream out = httpResp.getOutputStream();

                            if (error == null) {
                                cmsReq.setStatus(CMSRequest.SUCCESS);
                                httpResp.setContentType("text/html");
                                form.renderOutput(out, argSet);
                            } else {
                                cmsReq.setStatus(CMSRequest.ERROR);
                                cmsReq.setError(error);
                            }
                        } catch (IOException e) {
                            log(ILogger.LL_FAILURE,
                                CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
                            throw new ECMSGWException(
                              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
                        }
                    }
                } catch (Exception e) {
                }
            }
        }
    }

    private String getGroupName(String uid, String subsystemname) {
        String groupname = "";
        IUGSubsystem subsystem = 
          (IUGSubsystem)(CMS.getSubsystem(IUGSubsystem.ID)); 
        if (subsystem.isMemberOf(uid, "Enterprise CA Administrators") && 
          subsystemname.equals("CA")) {
            return "Enterprise CA Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise KRA Administrators") &&
          subsystemname.equals("KRA")) {
            return "Enterprise KRA Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise OCSP Administrators") &&
          subsystemname.equals("OCSP")) {
            return "Enterprise OCSP Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise TKS Administrators") &&
          subsystemname.equals("TKS")) {
            return "Enterprise TKS Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise RA Administrators") &&
          subsystemname.equals("RA")) {
            return "Enterprise RA Administrators";
        } else if (subsystem.isMemberOf(uid, "Enterprise TPS Administrators") &&
          subsystemname.equals("TPS")) {
            return "Enterprise TPS Administrators";
        }

        return null;
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
