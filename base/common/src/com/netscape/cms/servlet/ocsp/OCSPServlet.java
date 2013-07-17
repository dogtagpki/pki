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
package com.netscape.cms.servlet.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mozilla.jss.asn1.ASN1Util;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;
import com.netscape.cmsutil.util.Utils;

/**
 * Process OCSP messages, According to RFC 2560
 * See http://www.ietf.org/rfc/rfc2560.txt
 *
 * @version $Revision$ $Date$
 */
public class OCSPServlet extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 120903601883352030L;
    public final static String PROP_AUTHORITY = "authority";
    public final static String PROP_CLIENTAUTH = "GetClientCert";
    public final static String PROP_MAX_REQUEST_SIZE = "MaxRequestSize";
    public final static String PROP_ID = "ID";

    private int m_maxRequestSize = 5000;

    public OCSPServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "ImportCert.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        String s = sc.getInitParameter(PROP_MAX_REQUEST_SIZE);
        if (s != null) {
            try {
                m_maxRequestSize = Integer.parseInt(s);
            } catch (Exception e) {
            }
        }

    }

    /**
     * Process the HTTP request.
     * This method is invoked when the OCSP service receives a OCSP
     * request. Based on RFC 2560, the request should have the OCSP
     * request in the HTTP body as binary blob.
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("ocsp", true /* main action */);
        }

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

        CMS.debug("Servlet Path=" + httpReq.getServletPath());
        CMS.debug("RequestURI=" + httpReq.getRequestURI());
        String pathInfo = httpReq.getPathInfo();
        if (pathInfo != null && pathInfo.indexOf('%') != -1) {
            try {
                pathInfo = URLDecoder.decode(pathInfo, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                throw new EBaseException("OCSPServlet: Unsupported encoding" + e);
            }
        }
        CMS.debug("PathInfo=" + pathInfo);

        OCSPRequest ocspReq = null;

        try {
            InputStream is = httpReq.getInputStream();
            byte reqbuf[] = null;
            String method = httpReq.getMethod();
            CMS.debug("Method=" + method);
            if (method != null && method.equals("POST")) {
                int reqlen = httpReq.getContentLength();

                if (reqlen == -1) {
                    throw new Exception("OCSPServlet: Content-Length not supplied");
                }
                if (reqlen == 0) {
                    throw new Exception("OCSPServlet: Invalid Content-Length");
                }
                if (reqlen > m_maxRequestSize) {
                    throw new Exception("OCSPServlet: Client sending too much OCSP request data (" + reqlen + ")");
                }

                // for debugging
                reqbuf = new byte[reqlen];
                int bytesread = 0;
                boolean partial = false;

                while (bytesread < reqlen) {
                    int r = is.read(reqbuf, bytesread, reqlen - bytesread);
                    if (r == -1) {
                        throw new Exception("OCSPServlet: Client did not supply enough OCSP data");
                    }
                    bytesread += r;
                    if (partial == false) {
                        if (bytesread < reqlen) {
                            partial = true;
                        }
                    }
                }
                is = new ByteArrayInputStream(reqbuf);
            } else {
                // GET method
                if ((pathInfo == null) ||
                        (pathInfo.equals("")) ||
                        (pathInfo.substring(1) == null) ||
                        (pathInfo.substring(1).equals(""))) {
                    throw new Exception("OCSPServlet: OCSP request not provided in GET method");
                }
                is = new ByteArrayInputStream(
                        Utils.base64decode(pathInfo.substring(1)));
            }

            // (1) retrieve OCSP request
            // (2) decode request
            OCSPResponse response = null;

            try {
                OCSPRequest.Template reqTemplate =
                        new OCSPRequest.Template();

                if ((is == null) ||
                        (is.toString().equals(""))) {
                    throw new Exception("OCSPServlet: OCSP request is "
                                       + "empty or malformed");
                }
                ocspReq = (OCSPRequest) reqTemplate.decode(is);
                if ((ocspReq == null) ||
                        (ocspReq.toString().equals(""))) {
                    throw new Exception("OCSPServlet: Decoded OCSP request "
                                       + "is empty or malformed");
                }
                response = ((IOCSPService) mAuthority).validate(ocspReq);
            } catch (Exception e) {
                ;
                CMS.debug("OCSPServlet: " + e.toString());
            }

            if (response != null) {
                ByteArrayOutputStream fos1 = new ByteArrayOutputStream();

                response.encode(fos1);
                fos1.close();

                byte[] respbytes;

                respbytes = fos1.toByteArray();

                // print out OCSP response in debug mode so that
                // we can validate the response
                if (CMS.debugOn()) {
                    CMS.debug("OCSPServlet: OCSP Request:");
                    CMS.debug("OCSPServlet: " + CMS.BtoA(ASN1Util.encode(ocspReq)));
                    TBSRequest tbsReq = ocspReq.getTBSRequest();
                    for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                        com.netscape.cmsutil.ocsp.Request req = tbsReq.getRequestAt(i);
                        CMS.debug("Serial Number: " + req.getCertID().getSerialNumber());
                    }
                    CMS.debug("OCSPServlet: OCSP Response Size:");
                    CMS.debug("OCSPServlet: " + Integer.toString(respbytes.length));
                    CMS.debug("OCSPServlet: OCSP Response Data:");
                    CMS.debug("OCSPServlet: " + CMS.BtoA(respbytes));
                    ResponseBytes rbytes = response.getResponseBytes();
                    if (rbytes == null) {
                        CMS.debug("Response bytes is null");
                    } else if (rbytes.getObjectIdentifier().equals(
                               ResponseBytes.OCSP_BASIC)) {
                        BasicOCSPResponse basicRes = (BasicOCSPResponse)
                                BasicOCSPResponse.getTemplate().decode(
                                        new ByteArrayInputStream(rbytes.getResponse().toByteArray()));
                        if (basicRes == null) {
                            CMS.debug("Basic Res is null");
                        } else {
                            ResponseData data = basicRes.getResponseData();
                            for (int i = 0; i < data.getResponseCount(); i++) {
                                SingleResponse res = data.getResponseAt(i);
                                CMS.debug("Serial Number: " +
                                          res.getCertID().getSerialNumber() +
                                          " Status: " +
                                          res.getCertStatus().getClass().getName());
                            }
                        }
                    }
                }

                httpResp.setContentType("application/ocsp-response");

                httpResp.setContentLength(respbytes.length);
                OutputStream ooss = httpResp.getOutputStream();

                ooss.write(respbytes);
                ooss.flush();
                if (statsSub != null) {
                    statsSub.endTiming("ocsp");
                }

                mRenderResult = false;
            }
        } catch (Exception e) {
            CMS.debug("OCSPServlet: " + e.toString());
        }
    }
}
