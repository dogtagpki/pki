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
import java.util.Locale;
import java.util.Vector;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;

import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;

/**
 * Get detailed information about CA CRL processing
 */
@WebServlet(
        name = "caGetInfo",
        urlPatterns = "/ee/ca/getInfo",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="ID",            value="caGetInfo"),
                @WebInitParam(name="resourceID",    value="certServer.ee.crl"),
                @WebInitParam(name="interface",     value="ee")
        }
)
public class GetInfo extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(GetInfo.class);
    private static final long serialVersionUID = 1909881831730252799L;

    private CertificateAuthority mCA;

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
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CAEngine engine = CAEngine.getInstance();
        mCA = engine.getCA();

        // override success to do output our own template.
        mTemplates.remove(CMSRequest.SUCCESS);
    }

    /**
     * XXX Process the HTTP request.
     * <ul>
     * <li>http.param template filename of template to use to render the result
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        AuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        EBaseException error = null;

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
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
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE_1"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        logger.debug("*** formFile = " + formFile);
        try {
            form = getTemplate(formFile, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", formFile, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        try {
            process(header);
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
                    cmsReq.setStatus(CMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
    }

    private void process(ArgBlock header) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig cs = engine.getConfig();
        CRLRepository crlRepository = engine.getCRLRepository();

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

            String masterHost = cs.getString("master.ca.agent.host", "");
            String masterPort = cs.getString("master.ca.agent.port", "");

            if (masterHost != null && masterHost.length() > 0 &&
                    masterPort != null && masterPort.length() > 0) {

                Vector<String> ipNames = crlRepository.getIssuingPointsNames();
                for (int i = 0; i < ipNames.size(); i++) {
                    String ipName = ipNames.elementAt(i);
                    CRLIssuingPointRecord crlRecord = null;
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
                for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
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
                        if (ip.isCRLUpdateInProgress() == CRLIssuingPoint.CRL_PUBLISHING_STARTED) {
                            recentChanges += "Publishing CRL #" + ip.getCRLNumber();
                        } else if (ip.isCRLUpdateInProgress() == CRLIssuingPoint.CRL_UPDATE_STARTED) {
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

            header.addStringValue("masterCRLIssuingPoint", CertificateAuthority.PROP_MASTER_CRL);

            CRLIssuingPoint ip0 = engine.getCRLIssuingPoint(CertificateAuthority.PROP_MASTER_CRL);

            if (ip0 != null) {
                header.addStringValue("defaultAlgorithm", ip0.getSigningAlgorithm());
            }

            if (recentChanges.length() > 0)
                header.addStringValue("recentChanges", recentChanges);

            String validAlgorithms = null;
            String[] allAlgorithms = mCA.getCASigningAlgorithms();

            if (allAlgorithms == null) {
                logger.debug("GetInfo: signing algorithms set to All algorithms");
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
    }
}
