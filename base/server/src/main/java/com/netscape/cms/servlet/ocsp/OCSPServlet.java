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

import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.event.OCSPGenerationEvent;
import com.netscape.certsrv.ocsp.IOCSPService;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;

/**
 * Process OCSP messages, According to RFC 2560
 * See http://www.ietf.org/rfc/rfc2560.txt
 *
 * @version $Revision$ $Date$
 */
public class OCSPServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPServlet.class);

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
    @Override
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
    @Override
    protected void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMSEngine engine = CMS.getCMSEngine();
        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
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

        logger.debug("OCSPServlet: Servlet Path: " + httpReq.getServletPath());
        logger.debug("OCSPServlet: RequestURI: " + httpReq.getRequestURI());

        String pathInfo = httpReq.getPathInfo();
        if (pathInfo != null && pathInfo.indexOf('%') != -1) {
            try {
                pathInfo = URLDecoder.decode(pathInfo, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                logger.error("OCSPServlet: " + e.getMessage(), e);
                throw new EBaseException("OCSPServlet: Unsupported encoding: " + e, e);
            }
        }
        logger.debug("OCSPServlet: PathInfo: " + pathInfo);

        OCSPRequest ocspReq = null;

        try {
            InputStream is = httpReq.getInputStream();
            byte reqbuf[] = null;

            String method = httpReq.getMethod();
            logger.debug("OCSPServlet: HTTP method: " + method);

            if (method != null && method.equals("POST")) {

                logger.debug("OCSPServlet: processing POST request");

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

                logger.debug("OCSPServlet: processing GET request");

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

                logger.debug("OCSPServlet: decoding request");
                ocspReq = (OCSPRequest) reqTemplate.decode(is);

                if ((ocspReq == null) ||
                        (ocspReq.toString().equals(""))) {
                    throw new Exception("OCSPServlet: Decoded OCSP request "
                                       + "is empty or malformed");
                }

                logger.debug("OCSPServlet: validating request");
                response = ((IOCSPService) mAuthority).validate(ocspReq);

                if (response == null) {
                    audit(OCSPGenerationEvent.createFailureEvent(auditSubjectID(), "Missing OCSP response"));

                } else {
                    audit(OCSPGenerationEvent.createSuccessEvent(auditSubjectID()));
                }

            } catch (Exception e) {
                logger.warn("OCSPServlet: " + e.getMessage(), e);
                audit(OCSPGenerationEvent.createFailureEvent(auditSubjectID(), e.getMessage()));
            }

            if (response != null) {
                ByteArrayOutputStream fos1 = new ByteArrayOutputStream();

                response.encode(fos1);
                fos1.close();

                byte[] respbytes;

                respbytes = fos1.toByteArray();

                // print out OCSP response in debug mode so that
                // we can validate the response
                if (logger.isDebugEnabled()) {
                    logger.debug("OCSPServlet: OCSP Request:");
                    logger.debug("OCSPServlet: " + Utils.base64encode(ASN1Util.encode(ocspReq), true));

                    TBSRequest tbsReq = ocspReq.getTBSRequest();
                    for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                        com.netscape.cmsutil.ocsp.Request req = tbsReq.getRequestAt(i);
                        logger.debug("Serial Number: " + req.getCertID().getSerialNumber());
                    }

                    logger.debug("OCSPServlet: OCSP Response Size:");
                    logger.debug("OCSPServlet: " + Integer.toString(respbytes.length));
                    logger.debug("OCSPServlet: OCSP Response Data:");
                    logger.debug("OCSPServlet: " + Utils.base64encode(respbytes, true));

                    ResponseBytes rbytes = response.getResponseBytes();
                    if (rbytes == null) {
                        logger.debug("OCSPServlet: Response bytes is null");

                    } else if (rbytes.getObjectIdentifier().equals(
                               ResponseBytes.OCSP_BASIC)) {

                        BasicOCSPResponse basicRes = (BasicOCSPResponse)
                                BasicOCSPResponse.getTemplate().decode(
                                        new ByteArrayInputStream(rbytes.getResponse().toByteArray()));

                        if (basicRes == null) {
                            logger.warn("OCSPServlet: Basic Res is null");

                        } else {
                            ResponseData data = basicRes.getResponseData();
                            for (int i = 0; i < data.getResponseCount(); i++) {
                                SingleResponse res = data.getResponseAt(i);
                                logger.debug("OCSPServlet: Serial Number: " +
                                          res.getCertID().getSerialNumber());
                                logger.debug("OCSPServlet: Status: " +
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

            } else {
                logger.warn("OCSPServlet: response is null");
            }

        } catch (Exception e) {
            logger.warn("OCSPServlet: " + e.getMessage(), e);
        }
    }
}
