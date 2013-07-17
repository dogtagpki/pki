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
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.EErrorPublishCRL;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.ILdapRule;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Force the CRL to be updated now.
 *
 * @version $Revision$, $Date$
 */
public class UpdateCRL extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -1182106454856991246L;
    private final static String TPL_FILE = "updateCRL.template";

    private static Vector<String> mTesting = new Vector<String>();

    private String mFormPath = null;
    private ICertificateAuthority mCA = null;

    /**
     * Constructs UpdateCRL servlet.
     */
    public UpdateCRL() {
        super();
    }

    /**
     * Initializes the servlet. This servlet uses updateCRL.template
     * to render the result
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        if (mAuthority instanceof ICertificateAuthority)
            mCA = (ICertificateAuthority) mAuthority;

        // override success to do output orw own template.
        mTemplates.remove(ICMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param signatureAlgorithm the algorithm to use to sign the CRL
     * <li>http.param waitForUpdate true/false - should the servlet wait until the CRL update is complete?
     * <li>http.param clearCRLCache true/false - should the CRL cache cleared before the CRL is generated?
     * <li>http.param crlIssuingPoint the CRL Issuing Point to Update
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming("crl", true /* main action */);
        }

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;
        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "update");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            if (statsSub != null) {
                statsSub.endTiming("crl");
            }
            return;
        }

        EBaseException error = null;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            if (statsSub != null) {
                statsSub.endTiming("crl");
            }
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            String signatureAlgorithm =
                    req.getParameter("signatureAlgorithm");

            process(argSet, header, req, resp,
                    signatureAlgorithm, locale[0]);
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
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE",
                            e.toString()));
            if (statsSub != null) {
                statsSub.endTiming("crl");
            }
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        if (statsSub != null) {
            statsSub.endTiming("crl");
        }
    }

    private CRLExtensions crlEntryExtensions(String reason, String invalidity) {
        CRLExtensions entryExts = new CRLExtensions();

        CRLReasonExtension crlReasonExtn = null;
        if (reason != null && reason.length() > 0) {
            try {
                RevocationReason revReason = RevocationReason.fromInt(Integer.parseInt(reason));
                if (revReason == null)
                    revReason = RevocationReason.UNSPECIFIED;
                crlReasonExtn = new CRLReasonExtension(revReason);
            } catch (Exception e) {
                CMS.debug("Invalid revocation reason: " + reason);
            }
        }

        InvalidityDateExtension invalidityDateExtn = null;
        if (invalidity != null && invalidity.length() > 0) {
            long now = System.currentTimeMillis();
            Date invalidityDate = null;
            try {
                long backInTime = Long.parseLong(invalidity);
                invalidityDate = new Date(now - (backInTime * 60000));
            } catch (Exception e) {
                CMS.debug("Invalid invalidity time offset: " + invalidity);
            }
            if (invalidityDate != null) {
                try {
                    invalidityDateExtn = new InvalidityDateExtension(invalidityDate);
                } catch (Exception e) {
                    CMS.debug("Error creating invalidity extension: " + e);
                }
            }
        }

        if (crlReasonExtn != null) {
            try {
                entryExts.set(crlReasonExtn.getName(), crlReasonExtn);
            } catch (Exception e) {
                CMS.debug("Error adding revocation reason extension to entry extensions: " + e);
            }
        }

        if (invalidityDateExtn != null) {
            try {
                entryExts.set(invalidityDateExtn.getName(), invalidityDateExtn);
            } catch (Exception e) {
                CMS.debug("Error adding invalidity date extension to entry extensions: " + e);
            }
        }

        return entryExts;
    }

    private void addInfo(CMSTemplateParams argSet, ICRLIssuingPoint crlIssuingPoint, long cacheUpdate) {
        IArgBlock rarg = CMS.createArgBlock();

        rarg.addLongValue("cacheUpdate", cacheUpdate);

        String crlNumbers = crlIssuingPoint.getCRLNumber().toString();
        BigInteger deltaNumber = crlIssuingPoint.getDeltaCRLNumber();
        String crlSizes = "" + crlIssuingPoint.getCRLSize();
        if (deltaNumber != null && deltaNumber.compareTo(BigInteger.ZERO) > 0) {
            if (crlNumbers != null)
                crlNumbers += ",";
            if (crlNumbers != null)
                crlNumbers += deltaNumber.toString();
            if (crlSizes != null)
                crlSizes += "," + crlIssuingPoint.getDeltaCRLSize();
        }
        rarg.addStringValue("crlNumbers", crlNumbers);
        rarg.addStringValue("crlSizes", crlSizes);

        StringBuffer crlSplits = new StringBuffer();
        Vector<Long> splits = crlIssuingPoint.getSplitTimes();
        for (int i = 0; i < splits.size(); i++) {
            crlSplits.append(splits.elementAt(i));
            if (i + 1 < splits.size())
                crlSplits.append(",");
        }
        rarg.addStringValue("crlSplits", crlSplits.toString());

        argSet.addRepeatRecord(rarg);
    }

    private void process(CMSTemplateParams argSet, IArgBlock header,
            HttpServletRequest req,
            HttpServletResponse resp,
            String signatureAlgorithm,
            Locale locale)
            throws EBaseException {
        long startTime = CMS.getCurrentDate().getTime();
        String waitForUpdate =
                req.getParameter("waitForUpdate");
        String clearCache =
                req.getParameter("clearCRLCache");
        String crlIssuingPointId =
                req.getParameter("crlIssuingPoint");
        String test = req.getParameter("test");
        String add = req.getParameter("add");
        String from = req.getParameter("from");
        String by = req.getParameter("by");
        String reason = req.getParameter("reason");
        String invalidity = req.getParameter("invalidity");
        String results = req.getParameter("results");

        if (crlIssuingPointId != null) {
            Enumeration<ICRLIssuingPoint> ips = mCA.getCRLIssuingPoints();

            while (ips.hasMoreElements()) {
                ICRLIssuingPoint ip = ips.nextElement();

                if (crlIssuingPointId.equals(ip.getId())) {
                    break;
                }
                if (!ips.hasMoreElements())
                    crlIssuingPointId = null;
            }
        }
        if (crlIssuingPointId == null) {
            crlIssuingPointId = ICertificateAuthority.PROP_MASTER_CRL;
        }

        ICRLIssuingPoint crlIssuingPoint =
                mCA.getCRLIssuingPoint(crlIssuingPointId);
        header.addStringValue("crlIssuingPoint", crlIssuingPointId);
        IPublisherProcessor lpm = mCA.getPublisherProcessor();

        if (crlIssuingPoint != null) {
            if (clearCache != null && clearCache.equals("true") &&
                    crlIssuingPoint.isCRLGenerationEnabled() &&
                    crlIssuingPoint.isCRLUpdateInProgress() == ICRLIssuingPoint.CRL_UPDATE_DONE &&
                    crlIssuingPoint.isCRLIssuingPointInitialized()
                                == ICRLIssuingPoint.CRL_IP_INITIALIZED) {
                crlIssuingPoint.clearCRLCache();
            }
            if (waitForUpdate != null && waitForUpdate.equals("true") &&
                    crlIssuingPoint.isCRLGenerationEnabled() &&
                    crlIssuingPoint.isCRLUpdateInProgress() == ICRLIssuingPoint.CRL_UPDATE_DONE &&
                    crlIssuingPoint.isCRLIssuingPointInitialized()
                                == ICRLIssuingPoint.CRL_IP_INITIALIZED) {
                if (test != null && test.equals("true") &&
                        crlIssuingPoint.isCRLCacheTestingEnabled() &&
                        (!mTesting.contains(crlIssuingPointId))) {
                    CMS.debug("CRL test started.");
                    mTesting.add(crlIssuingPointId);
                    BigInteger addLen = null;
                    BigInteger startFrom = null;
                    if (add != null && add.length() > 0 &&
                            from != null && from.length() > 0) {
                        try {
                            addLen = new BigInteger(add);
                            startFrom = new BigInteger(from);
                        } catch (Exception e) {
                        }
                    }
                    if (addLen != null && startFrom != null) {
                        Date revocationDate = CMS.getCurrentDate();
                        String err = null;

                        CRLExtensions entryExts = crlEntryExtensions(reason, invalidity);

                        BigInteger serialNumber = startFrom;
                        BigInteger counter = addLen;
                        BigInteger stepBy = null;
                        if (by != null && by.length() > 0) {
                            try {
                                stepBy = new BigInteger(by);
                            } catch (Exception e) {
                            }
                        }

                        long t1 = System.currentTimeMillis();
                        long t2 = 0;

                        while (counter.compareTo(BigInteger.ZERO) > 0) {
                            RevokedCertImpl revokedCert =
                                    new RevokedCertImpl(serialNumber, revocationDate, entryExts);
                            crlIssuingPoint.addRevokedCert(serialNumber, revokedCert);
                            serialNumber = serialNumber.add(BigInteger.ONE);
                            counter = counter.subtract(BigInteger.ONE);

                            if ((counter.compareTo(BigInteger.ZERO) == 0) ||
                                    (stepBy != null && ((counter.mod(stepBy)).compareTo(BigInteger.ZERO) == 0))) {
                                t2 = System.currentTimeMillis();
                                long t0 = t2 - t1;
                                t1 = t2;
                                try {
                                    if (signatureAlgorithm != null) {
                                        crlIssuingPoint.updateCRLNow(signatureAlgorithm);
                                    } else {
                                        crlIssuingPoint.updateCRLNow();
                                    }
                                } catch (Throwable e) {
                                    counter = BigInteger.ZERO;
                                    err = e.toString();
                                }
                                if (results != null && results.equals("1")) {
                                    addInfo(argSet, crlIssuingPoint, t0);
                                }
                            }
                        }
                        if (err != null) {
                            header.addStringValue("crlUpdate", "Failure");
                            header.addStringValue("error", err);
                        } else {
                            header.addStringValue("crlUpdate", "Success");
                        }
                    } else {
                        CMS.debug("CRL test error: missing parameters.");
                        header.addStringValue("crlUpdate", "missingParameters");
                    }

                    mTesting.remove(crlIssuingPointId);
                    CMS.debug("CRL test finished.");
                } else if (test != null && test.equals("true") &&
                           crlIssuingPoint.isCRLCacheTestingEnabled() &&
                           mTesting.contains(crlIssuingPointId)) {
                    header.addStringValue("crlUpdate", "testingInProgress");
                } else if (test != null && test.equals("true") &&
                           (!crlIssuingPoint.isCRLCacheTestingEnabled())) {
                    header.addStringValue("crlUpdate", "testingNotEnabled");
                } else {
                    try {
                        EBaseException publishError = null;

                        try {
                            long now1 = System.currentTimeMillis();

                            if (signatureAlgorithm != null) {
                                crlIssuingPoint.updateCRLNow(signatureAlgorithm);
                            } else {
                                crlIssuingPoint.updateCRLNow();
                            }

                            long now2 = System.currentTimeMillis();

                            header.addStringValue("time", "" + (now2 - now1));
                        } catch (EErrorPublishCRL e) {
                            publishError = e;
                        }

                        if (lpm != null && lpm.enabled()) {
                            Enumeration<ILdapRule> rules = lpm.getRules(IPublisherProcessor.PROP_LOCAL_CRL);
                            if (rules != null && rules.hasMoreElements()) {
                                if (publishError != null) {
                                    header.addStringValue("crlPublished", "Failure");
                                    header.addStringValue("error", publishError.toString(locale));
                                } else {
                                    header.addStringValue("crlPublished", "Success");
                                }
                            }
                        }

                        // for audit log
                        SessionContext sContext = SessionContext.getContext();
                        String agentId = (String) sContext.get(SessionContext.USER_ID);
                        IAuthToken authToken = (IAuthToken) sContext.get(SessionContext.AUTH_TOKEN);
                        String authMgr = AuditFormat.NOAUTH;

                        if (authToken != null) {
                            authMgr = authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
                        }
                        long endTime = CMS.getCurrentDate().getTime();

                        if (crlIssuingPoint.getNextUpdate() != null) {
                            mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.CRLUPDATEFORMAT,
                                    new Object[] {
                                            AuditFormat.FROMAGENT + " agentID: " + agentId,
                                            authMgr,
                                            "completed",
                                            crlIssuingPoint.getId(),
                                            crlIssuingPoint.getCRLNumber(),
                                            crlIssuingPoint.getLastUpdate(),
                                            crlIssuingPoint.getNextUpdate(),
                                            Long.toString(crlIssuingPoint.getCRLSize())
                                                    + " time: " + (endTime - startTime) }
                                    );
                        } else {
                            mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.CRLUPDATEFORMAT,
                                    new Object[] {
                                            AuditFormat.FROMAGENT + " agentID: " + agentId,
                                            authMgr,
                                            "completed",
                                            crlIssuingPoint.getId(),
                                            crlIssuingPoint.getCRLNumber(),
                                            crlIssuingPoint.getLastUpdate(),
                                            "not set",
                                            Long.toString(crlIssuingPoint.getCRLSize())
                                                    + " time: " + (endTime - startTime) }
                                    );
                        }
                    } catch (EBaseException e) {
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_UPDATE_CRL", e.toString()));
                        if ((lpm != null) && lpm.enabled() && (e instanceof ELdapException)) {
                            header.addStringValue("crlPublished", "Failure");
                            header.addStringValue("error", e.toString(locale));
                        } else {
                            throw e;
                        }
                    }
                }
            } else {
                if (crlIssuingPoint.isCRLIssuingPointInitialized() != ICRLIssuingPoint.CRL_IP_INITIALIZED) {
                    header.addStringValue("crlUpdate", "notInitialized");
                } else if (crlIssuingPoint.isCRLUpdateInProgress()
                           != ICRLIssuingPoint.CRL_UPDATE_DONE ||
                           crlIssuingPoint.isManualUpdateSet()) {
                    header.addStringValue("crlUpdate", "inProgress");
                } else if (!crlIssuingPoint.isCRLGenerationEnabled()) {
                    header.addStringValue("crlUpdate", "Disabled");
                } else {
                    crlIssuingPoint.setManualUpdate(signatureAlgorithm);
                    header.addStringValue("crlUpdate", "Scheduled");
                }
            }
        }
        return;
    }
}
