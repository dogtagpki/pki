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
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.AlgorithmId;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.crldb.ICRLRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Get detailed information about CA CRL processing
 *
 * @version $Revision$, $Date$
 */
public class GetInfo extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 1909881831730252799L;

    private ICertificateAuthority mCA = null;

    /**
     * Constructs GetInfo servlet.
     */
    public GetInfo() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        if (mAuthority instanceof ICertificateAuthority)
            mCA = (ICertificateAuthority) mAuthority;

        // override success to do output our own template.
        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * XXX Process the HTTP request.
     * <ul>
     * <li>http.param template filename of template to use to render the result
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        EBaseException error = null;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        String template = req.getParameter("template");
        String formFile = "";

        /*
                for (int i = 0; ((template != null) && (i < template.length())); i++) {
                    char c = template.charAt(i);
                    if (!Character.isLetterOrDigit(c) && c != '_' && c != '-') {
                        template = null;
                        break;
                    }
                }
        */

        if (template != null) {
            formFile = template + ".template";
        } else {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE_1"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        CMS.debug("*** formFile = " + formFile);
        try {
            form = getTemplate(formFile, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", formFile, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            process(argSet, header, req, resp, locale[0]);
        } catch (EBaseException e) {
            error = e;
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                    outputXML(resp, argSet);
                } else {
                    resp.setContentType("text/html");
                    form.renderOutput(out, argSet);
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(ICMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    private void process(CMSTemplateParams argSet, IArgBlock header,
            HttpServletRequest req,
            HttpServletResponse resp,
            Locale locale)
            throws EBaseException {
        if (mCA != null) {
            String crlIssuingPoints = "";
            String crlNumbers = "";
            String deltaNumbers = "";
            String crlSizes = "";
            String deltaSizes = "";
            String crlDescriptions = "";
            StringBuffer crlSplits = new StringBuffer();
            String recentChanges = "";
            String crlTesting = "";
            boolean isDeltaCRLEnabled = false;

            String masterHost = CMS.getConfigStore().getString("master.ca.agent.host", "");
            String masterPort = CMS.getConfigStore().getString("master.ca.agent.port", "");

            if (masterHost != null && masterHost.length() > 0 &&
                    masterPort != null && masterPort.length() > 0) {

                ICRLRepository crlRepository = mCA.getCRLRepository();

                Vector<String> ipNames = crlRepository.getIssuingPointsNames();
                for (int i = 0; i < ipNames.size(); i++) {
                    String ipName = ipNames.elementAt(i);
                    ICRLIssuingPointRecord crlRecord = null;
                    try {
                        crlRecord = crlRepository.readCRLIssuingPointRecord(ipName);
                    } catch (Exception e) {
                    }
                    if (crlRecord != null) {
                        if (crlIssuingPoints.length() > 0)
                            crlIssuingPoints += "+";
                        crlIssuingPoints += ipName;

                        BigInteger crlNumber = crlRecord.getCRLNumber();
                        if (crlNumbers.length() > 0)
                            crlNumbers += "+";
                        if (crlNumber != null)
                            crlNumbers += crlNumber.toString();

                        if (crlSizes.length() > 0)
                            crlSizes += "+";
                        crlSizes += ((crlRecord.getCRLSize() != null) ?
                                      crlRecord.getCRLSize().toString() : "-1");

                        if (deltaSizes.length() > 0)
                            deltaSizes += "+";
                        long dSize = -1;
                        if (crlRecord.getDeltaCRLSize() != null)
                            dSize = crlRecord.getDeltaCRLSize().longValue();
                        deltaSizes += dSize;

                        BigInteger deltaNumber = crlRecord.getDeltaCRLNumber();
                        if (deltaNumbers.length() > 0)
                            deltaNumbers += "+";
                        if (deltaNumber != null && dSize > -1) {
                            deltaNumbers += deltaNumber.toString();
                            isDeltaCRLEnabled |= true;
                        } else {
                            deltaNumbers += "0";
                        }

                        if (recentChanges.length() > 0)
                            recentChanges += "+";
                        recentChanges += "-, -, -";

                        if (crlTesting.length() > 0)
                            crlTesting += "+";
                        crlTesting += "0";
                    }
                }

            } else {
                Enumeration<ICRLIssuingPoint> ips = mCA.getCRLIssuingPoints();

                while (ips.hasMoreElements()) {
                    ICRLIssuingPoint ip = ips.nextElement();

                    if (ip.isCRLIssuingPointEnabled()) {
                        if (crlIssuingPoints.length() > 0)
                            crlIssuingPoints += "+";
                        crlIssuingPoints += ip.getId();

                        BigInteger crlNumber = ip.getCRLNumber();
                        if (crlNumbers.length() > 0)
                            crlNumbers += "+";
                        if (crlNumber != null)
                            crlNumbers += crlNumber.toString();

                        BigInteger deltaNumber = ip.getDeltaCRLNumber();
                        if (deltaNumbers.length() > 0)
                            deltaNumbers += "+";
                        if (deltaNumber != null)
                            deltaNumbers += deltaNumber.toString();

                        if (crlSizes.length() > 0)
                            crlSizes += "+";
                        crlSizes += ip.getCRLSize();

                        if (deltaSizes.length() > 0)
                            deltaSizes += "+";
                        deltaSizes += ip.getDeltaCRLSize();

                        if (crlDescriptions.length() > 0)
                            crlDescriptions += "+";
                        crlDescriptions += ip.getDescription();

                        if (recentChanges.length() > 0)
                            recentChanges += "+";
                        if (ip.isCRLUpdateInProgress() == ICRLIssuingPoint.CRL_PUBLISHING_STARTED) {
                            recentChanges += "Publishing CRL #" + ip.getCRLNumber();
                        } else if (ip.isCRLUpdateInProgress() == ICRLIssuingPoint.CRL_UPDATE_STARTED) {
                            recentChanges += "Creating CRL #" + ip.getNextCRLNumber();
                        } else { // ip.CRL_UPDATE_DONE
                            recentChanges += ip.getNumberOfRecentlyRevokedCerts() + ", " +
                                    ip.getNumberOfRecentlyUnrevokedCerts() + ", " +
                                    ip.getNumberOfRecentlyExpiredCerts();
                        }
                        isDeltaCRLEnabled |= ip.isDeltaCRLEnabled();

                        if (crlSplits.length() > 0)
                            crlSplits.append("+");
                        Vector<Long> splits = ip.getSplitTimes();

                        for (int i = 0; i < splits.size(); i++) {
                            crlSplits.append(splits.elementAt(i));
                            if (i + 1 < splits.size())
                                crlSplits.append(",");
                        }

                        if (crlTesting.length() > 0)
                            crlTesting += "+";
                        crlTesting += ((ip.isCRLCacheTestingEnabled()) ? "1" : "0");
                    }
                }

            }

            header.addStringValue("crlIssuingPoints", crlIssuingPoints);
            header.addStringValue("crlDescriptions", crlDescriptions);
            header.addStringValue("crlNumbers", crlNumbers);
            header.addStringValue("deltaNumbers", deltaNumbers);
            header.addStringValue("crlSizes", crlSizes);
            header.addStringValue("deltaSizes", deltaSizes);
            header.addStringValue("crlSplits", crlSplits.toString());
            header.addStringValue("crlTesting", crlTesting);
            header.addBooleanValue("isDeltaCRLEnabled", isDeltaCRLEnabled);

            header.addStringValue("master_host", masterHost);
            header.addStringValue("master_port", masterPort);

            header.addStringValue("masterCRLIssuingPoint", ICertificateAuthority.PROP_MASTER_CRL);
            ICRLIssuingPoint ip0 = mCA.getCRLIssuingPoint(ICertificateAuthority.PROP_MASTER_CRL);

            if (ip0 != null) {
                header.addStringValue("defaultAlgorithm", ip0.getSigningAlgorithm());
            }

            if (recentChanges.length() > 0)
                header.addStringValue("recentChanges", recentChanges);

            String validAlgorithms = null;
            String[] allAlgorithms = mCA.getCASigningAlgorithms();

            if (allAlgorithms == null) {
                CMS.debug("GetInfo: signing algorithms set to All algorithms");
                allAlgorithms = AlgorithmId.ALL_SIGNING_ALGORITHMS;
            }

            for (int i = 0; i < allAlgorithms.length; i++) {
                if (i > 0) {
                    validAlgorithms += "+" + allAlgorithms[i];
                } else {
                    validAlgorithms = allAlgorithms[i];
                }
            }
            if (validAlgorithms != null)
                header.addStringValue("validAlgorithms", validAlgorithms);
        }

        return;
    }
}
