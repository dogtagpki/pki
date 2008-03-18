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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import java.security.cert.CRLException;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;

import com.netscape.cms.servlet.*;


/**
 * Decode the CRL and display it to the requester.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class DisplayCRL extends CMSServlet {

    private final static String INFO = "DisplayCRL";
    private final static String TPL_FILE = "displayCRL.template";
    //private final static String E_TPL_FILE = "error.template";
    //private final static String OUT_ERROR = "errorDetails";

    private String mFormPath = null;
    private ICertificateAuthority mCA = null;

    /**
     * Constructs DisplayCRL servlet.
     */
    public DisplayCRL() {
        super();
    }

    /**
     * Initialize the servlet. This servlet uses the 'displayCRL.template' file to
     * to render the response to the client.
	 * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        if (mAuthority instanceof ICertificateAuthority) {
            mCA = (ICertificateAuthority) mAuthority;
        }
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        mTemplates.remove(CMSRequest.SUCCESS);
    }

    /**
	 * Process the HTTP request
     * <ul>
     * <li>http.param  crlIssuingPoint number
     * <li>http.param  crlDisplayType entireCRL or crlHeader or base64Encoded or deltaCRL
     * <li>http.param  pageStart which page to start displaying from
     * <li>http.param  pageSize number of entries to show per page
     * </ul>
     * @param cmsReq the Request to service.

     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

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

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE_1", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        // Note error is covered in the same template as success.
        EBaseException error = null;

        String crlIssuingPointId = req.getParameter("crlIssuingPoint");

        process(argSet, header, req, resp, crlIssuingPointId,
            locale[0]);

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                  outputXML(resp, argSet);
                } else {
                  resp.setContentType("text/html");
                  form.renderOutput(out, argSet);
                  cmsReq.setStatus(CMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", e.toString()));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }
    }

    /**
     * Display information about a particular CRL.
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
                         HttpServletRequest req,
                         HttpServletResponse resp,
                         String crlIssuingPointId,
                         Locale locale) {
        boolean updateStatus = true;
        EBaseException error = null;
        ICRLIssuingPoint crlIP = null;
        X509CRLImpl crl = null;
        boolean clonedCA = false;
        String masterHost = null;
        String masterPort = null;
        Vector ipNames = null;
        String ipId = crlIssuingPointId;
        ICRLRepository crlRepository = mCA.getCRLRepository();

        try {
            masterHost = CMS.getConfigStore().getString("master.ca.agent.host", "");
            masterPort = CMS.getConfigStore().getString("master.ca.agent.port", "");
            if (masterHost != null && masterHost.length() > 0 &&
                masterPort != null && masterPort.length() > 0) {
                clonedCA = true;
                ipNames = crlRepository.getIssuingPointsNames();
            }
        } catch (EBaseException e) {
        }
            
        if (clonedCA) {
            if (crlIssuingPointId != null) {
                if (ipNames != null && ipNames.size() > 0) {
                    int i;
                    for (i = 0; i < ipNames.size(); i++) {
                        String ipName = (String)ipNames.elementAt(i);
                        if (crlIssuingPointId.equals(ipName)) {
                            break;
                        }
                    }
                    if (i >= ipNames.size()) crlIssuingPointId = null;
                } else {
                    crlIssuingPointId = null;
                }
            }
        } else {
            if (crlIssuingPointId != null) {
                Enumeration ips = mCA.getCRLIssuingPoints();

                while (ips.hasMoreElements()) {
                    ICRLIssuingPoint ip = (ICRLIssuingPoint) ips.nextElement();

                    if (crlIssuingPointId.equals(ip.getId())) {
                        crlIP = ip;
                        break;
                    }
                    if (!ips.hasMoreElements()) crlIssuingPointId = null;
                }
            }
        }
        if (crlIssuingPointId == null) {
            header.addStringValue("error",
                "Request to unspecified or non-existing CRL issuing point: "+ipId);
            return;
        }

        ICRLIssuingPointRecord crlRecord = null;

        String crlDisplayType = req.getParameter("crlDisplayType");

        if (crlDisplayType == null) crlDisplayType = "cachedCRL";
        header.addStringValue("crlDisplayType", crlDisplayType);

        try {
            crlRecord = 
                    (ICRLIssuingPointRecord) mCA.getCRLRepository().readCRLIssuingPointRecord(crlIssuingPointId);
        } catch (EBaseException e) {
            header.addStringValue("error", e.toString(locale));
            return;
        }
        if (crlRecord == null) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_CRL_NOT_YET_UPDATED_1", crlIssuingPointId));
            header.addStringValue("error", 
                new ECMSGWException(CMS.getUserMessage(locale, "CMS_GW_CRL_NOT_YET_UPDATED")).toString());
            return; 
        }

        header.addStringValue("crlIssuingPoint", crlIssuingPointId);
        if (crlDisplayType.equals("deltaCRL")) {
            if (clonedCA) {
                header.addStringValue("crlNumber", crlRecord.getDeltaCRLNumber().toString());
            } else {
                header.addStringValue("crlNumber", crlIP.getDeltaCRLNumber().toString());
            }
        } else {
            if (clonedCA) {
                header.addStringValue("crlNumber", crlRecord.getCRLNumber().toString());
            } else {
                header.addStringValue("crlNumber", crlIP.getCRLNumber().toString());
            }
        }
        long lCRLSize = crlRecord.getCRLSize().longValue();
        header.addLongValue("crlSize", lCRLSize);

        if (crlIP != null) {
            header.addStringValue("crlDescription", crlIP.getDescription());
        }

        if (!crlDisplayType.equals("cachedCRL")) {
            byte[] crlbytes = crlRecord.getCRL();

            if (crlbytes == null) {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("CMSGW_CRL_NOT_YET_UPDATED_1", crlIssuingPointId));
                header.addStringValue("error", 
                    new ECMSGWException(CMS.getUserMessage(locale, "CMS_GW_CRL_NOT_YET_UPDATED")).toString());
                return;
            }

            try {
                if (crlDisplayType.equals("crlHeader")) {
                    crl = new X509CRLImpl(crlbytes, false);
                } else {
                    crl = new X509CRLImpl(crlbytes);
                }

            } catch (Exception e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_DECODE_CRL", e.toString()));
                header.addStringValue("error", 
                    new ECMSGWException(CMS.getUserMessage(locale, "CMS_GW_DECODE_CRL_FAILED")).toString());
            }
        }

        if (crl != null || crlDisplayType.equals("cachedCRL")) {
            if (crlDisplayType.equals("entireCRL") || crlDisplayType.equals("cachedCRL")) {
                ICRLPrettyPrint crlDetails = null;
                if (crlDisplayType.equals("entireCRL")) {
                    crlDetails = CMS.getCRLPrettyPrint(crl);
                } else {
                    crlDetails = CMS.getCRLCachePrettyPrint(crlIP);
                }

                String pageStart = req.getParameter("pageStart");
                String pageSize = req.getParameter("pageSize");

                if (pageStart != null && pageSize != null) {
                    long lPageStart = new Long(pageStart).longValue();
                    long lPageSize = new Long(pageSize).longValue();

                    if (lPageStart < 1) lPageStart = 1;
                    // if (lPageStart + lPageSize - lCRLSize > 1)
                    //     lPageStart = lCRLSize - lPageSize + 1;

                    header.addStringValue(
                        "crlPrettyPrint", crlDetails.toString(locale,
                            lCRLSize, lPageStart, lPageSize));
                    header.addLongValue("pageStart", lPageStart);
                    header.addLongValue("pageSize", lPageSize);
                } else {
                    header.addStringValue(
                        "crlPrettyPrint", crlDetails.toString(locale));
                }
            } else if (crlDisplayType.equals("crlHeader")) {
                ICRLPrettyPrint crlDetails = CMS.getCRLPrettyPrint(crl);

                header.addStringValue(
                    "crlPrettyPrint", crlDetails.toString(locale, lCRLSize, 0, 0));
            } else if (crlDisplayType.equals("base64Encoded")) {
                try {
                    byte[] ba = crl.getEncoded();
                    String crlBase64Encoded = com.netscape.osutil.OSUtil.BtoA(ba);
                    int length = crlBase64Encoded.length();
                    int i = 0;
                    int j = 0;
                    int n = 1;

                    while (i < length) {
                        int k = crlBase64Encoded.indexOf('\n', i);

                        if (n < 100 && k > -1) {
                            n++;
                            i = k + 1;
                            if (i >= length) {
                                IArgBlock rarg = CMS.createArgBlock();

                                rarg.addStringValue("crlBase64Encoded", crlBase64Encoded.substring(j, k));
                                argSet.addRepeatRecord(rarg);
                            }
                        } else {
                            n = 1;
                            IArgBlock rarg = CMS.createArgBlock();

                            if (k > -1) {
                                rarg.addStringValue("crlBase64Encoded", crlBase64Encoded.substring(j, k));
                                i = k + 1;
                                j = i;
                            } else {
                                rarg.addStringValue("crlBase64Encoded", crlBase64Encoded.substring(j, length));
                                i = length;
                            }
                            argSet.addRepeatRecord(rarg);
                        }
                    }
                } catch (CRLException e) {
                }
            } else if (crlDisplayType.equals("deltaCRL")) {
                if ((clonedCA && crlRecord.getDeltaCRLSize() != null && 
                     crlRecord.getDeltaCRLSize().longValue() > -1) ||
                    (crlIP != null && crlIP.isDeltaCRLEnabled())) {
                    byte[] deltaCRLBytes = crlRecord.getDeltaCRL();

                    if (deltaCRLBytes == null) {
                        log(ILogger.LL_FAILURE, 
                            CMS.getLogMessage("CMSGW_ERR_NO_DELTA_CRL", crlIssuingPointId));
                        header.addStringValue("error", "Delta CRL is not available");
                    } else {
                        X509CRLImpl deltaCRL = null;

                        try {
                            deltaCRL = new X509CRLImpl(deltaCRLBytes);
                        } catch (Exception e) {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_DECODE_DELTA_CRL", e.toString()));
                            header.addStringValue("error", 
                              new ECMSGWException(CMS.getUserMessage(locale, "CMS_GW_DECODE_CRL_FAILED")).toString());
                        }
                        if (deltaCRL != null) {
                            BigInteger crlNumber = crlRecord.getCRLNumber();
                            BigInteger deltaNumber = crlRecord.getDeltaCRLNumber();
                            if ((clonedCA && crlNumber != null && deltaNumber != null &&
                                 deltaNumber.compareTo(crlNumber) >= 0) ||
                                (crlIP != null && crlIP.isThisCurrentDeltaCRL(deltaCRL))) {

                                header.addIntegerValue("deltaCRLSize",
                                    deltaCRL.getNumberOfRevokedCertificates());

                                ICRLPrettyPrint crlDetails = CMS.getCRLPrettyPrint(deltaCRL);

                                header.addStringValue(
                                    "crlPrettyPrint", crlDetails.toString(locale, 0, 0, 0));

                                try {
                                    byte[] ba = deltaCRL.getEncoded();
                                    String crlBase64Encoded = com.netscape.osutil.OSUtil.BtoA(ba);
                                    int length = crlBase64Encoded.length();
                                    int i = 0;
                                    int j = 0;
                                    int n = 1;

                                    while (i < length) {
                                        int k = crlBase64Encoded.indexOf('\n', i);

                                        if (n < 100 && k > -1) {
                                            n++;
                                            i = k + 1;
                                            if (i >= length) {
                                                IArgBlock rarg = CMS.createArgBlock();

                                                rarg.addStringValue("crlBase64Encoded", crlBase64Encoded.substring(j, k));
                                                argSet.addRepeatRecord(rarg);
                                            }
                                        } else {
                                            n = 1;
                                            IArgBlock rarg = CMS.createArgBlock();

                                            if (k > -1) {
                                                rarg.addStringValue("crlBase64Encoded", crlBase64Encoded.substring(j, k));
                                                i = k + 1;
                                                j = i;
                                            } else {
                                                rarg.addStringValue("crlBase64Encoded", crlBase64Encoded.substring(j, length));
                                                i = length;
                                            }
                                            argSet.addRepeatRecord(rarg);
                                        }
                                    }
                                } catch (CRLException e) {
                                }
                            } else {
                                header.addStringValue("error", "Current Delta CRL is not available.");
                            }
                        }
                    }
                } else {
                    header.addStringValue("error", "Delta CRL is not enabled for " +
                        crlIssuingPointId +
                        " issuing point");
                }
            }

        } else {
            header.addStringValue("error", 
                new ECMSGWException(CMS.getUserMessage(locale, "CMS_GW_DECODE_CRL_FAILED")).toString());
            header.addStringValue("crlPrettyPrint", 
                new ECMSGWException(CMS.getUserMessage(locale, "CMS_GW_DECODE_CRL_FAILED")).toString());
        }
        return;
    }
}
