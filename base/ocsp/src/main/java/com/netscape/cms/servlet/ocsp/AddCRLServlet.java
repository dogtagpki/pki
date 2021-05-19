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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.ocsp.OCSPEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.ocsp.OCSPAuthority;

/**
 * Update the OCSP responder with a new CRL
 *
 * @version $Revision$ $Date$
 */
public class AddCRLServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AddCRLServlet.class);

    private static final long serialVersionUID = 1476080474638590902L;
    public static final String BEGIN_HEADER =
            "-----BEGIN CERTIFICATE REVOCATION LIST-----";
    public static final String END_HEADER =
            "-----END CERTIFICATE REVOCATION LIST-----";

    private final static String TPL_FILE = "addCRL.template";
    private String mFormPath = null;
    private OCSPAuthority mOCSPAuthority;

    public AddCRLServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "addCRL.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to display own output.

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        mTemplates.remove(ICMSRequest.SUCCESS);
        mOCSPAuthority = (OCSPAuthority) mAuthority;
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     * <P>
     *
     * <ul>
     * <li>http.param crl certificate revocation list, base-64, DER encoded wrapped in -----BEGIN CERTIFICATE REVOCATION
     * LIST-----, -----END CERTIFICATE REVOCATION LIST----- strings
     * <li>http.param noui if true, use minimal hardcoded text response
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CRL_RETRIEVAL used when CRLs are retrieved by the OCSP Responder ("agent"
     * or "EE")
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CRL_VALIDATION used when CRL is retrieved and validation process occurs
     * ("agent" or "EE")
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     * @exception EBaseException an error has occurred
     */
    @Override
    protected synchronized void process(CMSRequest cmsReq)
            throws EBaseException {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPEngineConfig cs = engine.getConfig();

        boolean CRLFetched = false;
        boolean CRLValidated = false;
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditCRLNum = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        IStatsSubsystem statsSub = (IStatsSubsystem) engine.getSubsystem(IStatsSubsystem.ID);
        if (statsSub != null) {
            statsSub.startTiming("add_crl", true /* main action */);
        }

        try {
            HttpServletRequest req = cmsReq.getHttpReq();
            HttpServletResponse resp = cmsReq.getHttpResp();

            IAuthToken authToken = authenticate(cmsReq);

            AuthzToken authzToken = null;

            try {
                authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "add");
            } catch (Exception e) {
                // do nothing for now
            }

            if (authzToken == null) {
                cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);

                return;
            }

            if (auditSubjectID.equals(ILogger.NONROLEUSER) ||
                    auditSubjectID.equals(ILogger.UNIDENTIFIED)) {
                if (authToken != null) {
                    String uid = authToken.getInString(IAuthToken.USER_ID);
                    if (uid != null) {
                        logger.debug("AddCRLServlet: auditSubjectID set to " + uid);
                        auditSubjectID = uid;
                    }
                }
            }
            logger.info("AddCRLServlet");
            String b64 = cmsReq.getHttpReq().getParameter("crl");
            logger.debug("AddCRLServlet: b64=" + b64);

            if (b64 == null) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);

                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_MISSING_CRL"));
            }

            String nouiParm = cmsReq.getHttpReq().getParameter("noui");
            boolean noUI = false;

            if (nouiParm != null && nouiParm.equals("true")) {
                noUI = true;
                logger.debug("AddCRLServlet: noUI=true");
            } else {
                logger.debug("AddCRLServlet: noUI=false");
            }

            CMSTemplate form = null;
            Locale[] locale = new Locale[1];

            try {
                if (!noUI) {
                    form = getTemplate(mFormPath, req, locale);
                }
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);

                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
            }

            ArgBlock header = new ArgBlock();
            ArgBlock fixed = new ArgBlock();
            CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

            if (b64.indexOf(BEGIN_HEADER) == -1) {
                logger.error(CMS.getLogMessage("CMSGW_MISSING_CRL_HEADER"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);

                throw new ECMSGWException(CMS.getUserMessage(getLocale(req),
                                          "CMS_GW_MISSING_CRL_HEADER"));
            }
            if (b64.indexOf(END_HEADER) == -1) {
                logger.error(CMS.getLogMessage("CMSGW_MISSING_CRL_FOOTER"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);

                throw new ECMSGWException(CMS.getUserMessage(getLocale(req),
                                          "CMS_GW_MISSING_CRL_FOOTER"));
            }

            IDefStore defStore = mOCSPAuthority.getDefaultStore();

            X509CRLImpl crl = null;

            try {
                long startTime = new Date().getTime();
                logger.debug("AddCRLServlet: mapCRL start startTime=" + startTime);
                if (statsSub != null) {
                    statsSub.startTiming("decode_crl");
                }
                crl = mapCRL1(b64);
                if (statsSub != null) {
                    statsSub.endTiming("decode_crl");
                }
                long endTime = new Date().getTime();
                logger.debug("AddCRLServlet: mapCRL done endTime=" + endTime +
                        " diff=" + (endTime - startTime));

                // Retrieve the actual CRL number
                BigInteger crlNum = crl.getCRLNumber();
                if (crlNum != null) {
                    auditCRLNum = crlNum.toString();
                }

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditCRLNum);

                audit(auditMessage);

                // acknowledge that the CRL has been retrieved
                CRLFetched = true;
            } catch (Exception e) {
                // error

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);

                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_DECODING_CRL_ERROR"));
            }
            logger.info("AddCRLServlet: CRL Issuer DN " + crl.getIssuerDN().getName());

            ICRLIssuingPointRecord pt = null;

            try {
                pt = defStore.readCRLIssuingPoint(
                            crl.getIssuerDN().getName());
            } catch (Exception e) {
                logger.error(CMS.getLogMessage("CMSGW_NO_CRL_ISSUING_POINT_FOUND", crl.getIssuerDN().getName()), e);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_VALIDATION,
                        auditSubjectID,
                        ILogger.FAILURE);

                audit(auditMessage);

                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_DECODING_CRL_ERROR"));
            }
            logger.info("AddCRLServlet: IssuingPoint " + pt.getThisUpdate());

            // verify CRL
            CryptoManager cmanager = null;
            boolean tokenSwitched = false;
            CryptoToken verToken = null;
            CryptoToken savedToken = null;
            byte caCertData[] = pt.getCACert();
            if (caCertData != null) {
                try {
                    cmanager = CryptoManager.getInstance();
                    X509CertImpl caCert = new X509CertImpl(caCertData);
                    logger.debug("AddCRLServlet: start verify");

                    String tokenName = cs.getString("ocsp.crlVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                    savedToken = cmanager.getThreadToken();
                    verToken = CryptoUtil.getCryptoToken(tokenName);
                    if (!savedToken.getName().equals(verToken.getName())) {
                        cmanager.setThreadToken(verToken);
                        tokenSwitched = true;
                    }

                    org.mozilla.jss.crypto.X509Certificate jssCert = null;
                    try {
                        jssCert = cmanager.importCACertPackage(
                                caCert.getEncoded());
                    } catch (Exception e2) {
                        logger.error("AddCRLServlet: importCACertPackage: " + e2.getMessage(), e2);
                        throw new EBaseException(e2.toString());
                    }

                    if (statsSub != null) {
                        statsSub.startTiming("verify_crl");
                    }
                    crl.verify(jssCert.getPublicKey(), "Mozilla-JSS");
                    if (statsSub != null) {
                        statsSub.endTiming("verify_crl");
                    }
                    logger.debug("AddCRLServlet: done verify");

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.CRL_VALIDATION,
                            auditSubjectID,
                            ILogger.SUCCESS);

                    audit(auditMessage);

                    // acknowledge that the CRL has been validated
                    CRLValidated = true;
                } catch (Exception e) {
                    logger.error("AddCRLServlet: failed to verify CRL: " + e.getMessage(), e);
                    logger.error(CMS.getLogMessage("CMSGW_NO_CRL_ISSUING_POINT_FOUND", crl.getIssuerDN().getName()), e);

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.CRL_VALIDATION,
                            auditSubjectID,
                            ILogger.FAILURE);

                    audit(auditMessage);

                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_DECODING_CRL_ERROR"));
                } finally {
                    if (tokenSwitched == true){
                        cmanager.setThreadToken(savedToken);
                    }
                }
            }

            if ((pt.getThisUpdate() != null) &&
                    (pt.getThisUpdate().getTime() >=
                    crl.getThisUpdate().getTime())) {

                logger.warn("AddCRLServlet: no update, received CRL is older than current CRL");

                if (noUI) {
                    try {
                        resp.setContentType("application/text");
                        resp.getOutputStream().write("status=1\n".getBytes());
                        resp.getOutputStream().write(
                                "error=Sent CRL is older than the current CRL\n".getBytes());
                        resp.getOutputStream().flush();
                        cmsReq.setStatus(ICMSRequest.SUCCESS);

                        // NOTE:  The signed audit events
                        //        LOGGING_SIGNED_AUDIT_CRL_RETRIEVAL and
                        //        LOGGING_SIGNED_AUDIT_CRL_VALIDATION have
                        //        already been logged at this point!

                        return;
                    } catch (Exception e) {
                    }
                } else {
                    logger.error("AddCRLServlet: CRL is older");

                    // NOTE:  The signed audit events
                    //        LOGGING_SIGNED_AUDIT_CRL_RETRIEVAL and
                    //        LOGGING_SIGNED_AUDIT_CRL_VALIDATION have
                    //        already been logged at this point!

                    throw new ECMSGWException(CMS.getUserMessage(
                            "CMS_GW_OLD_CRL_ERROR"));
                }
            }

            if (crl.isDeltaCRL()) {

                logger.warn("AddCRLServlet: no update, " + CMS.getUserMessage("CMS_GW_DELTA_CRL_NOT_SUPPORTED"));

                if (noUI) {
                    try {
                        resp.setContentType("application/text");
                        resp.getOutputStream().write("status=1\n".getBytes());
                        resp.getOutputStream().write(
                                "error=Delta CRLs are not supported.\n".getBytes());
                        resp.getOutputStream().flush();
                        cmsReq.setStatus(ICMSRequest.SUCCESS);

                        return;
                    } catch (Exception e) {
                    }
                } else {
                    throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DELTA_CRL_NOT_SUPPORTED"));
                }
            }

            logger.info("AddCRLServlet: Start Committing CRL");

            // *****************************************************
            // The commit transaction may take long time and
            // there may have a system crash during the transaction
            // *****************************************************

            IRepositoryRecord repRec = defStore.createRepositoryRecord();

            repRec.set(IRepositoryRecord.ATTR_SERIALNO,
                    new BigInteger(Long.toString(crl.getThisUpdate().getTime())));
            try {
                defStore.addRepository(
                        crl.getIssuerDN().getName(),
                        Long.toString(crl.getThisUpdate().getTime()),
                        repRec);
                logger.info("AddCRLServlet: Added CRL Updated " + Long.toString(crl.getThisUpdate().getTime()));
            } catch (Exception e) {
                logger.warn("AddCRLServlet: add repository: " + e.getMessage(), e);
            }

            logger.info("AddCRLServlet: Created CRL Repository " + Long.toString(crl.getThisUpdate().getTime()));

            if (defStore.waitOnCRLUpdate()) {
                defStore.updateCRL(crl);
            } else {
                // when the CRL large, the thread is terminiated by the
                // servlet framework before it can finish its work
                UpdateCRLThread uct = new UpdateCRLThread(defStore, crl);

                uct.start();
            }

            try {
                ServletOutputStream out = resp.getOutputStream();

                if (noUI) {
                    logger.debug("AddCRLServlet: return result noUI=true");
                    resp.setContentType("application/text");
                    resp.getOutputStream().write("status=0".getBytes());
                    resp.getOutputStream().flush();
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                } else {
                    logger.debug("AddCRLServlet: return result noUI=false");
                    String xmlOutput = req.getParameter("xml");
                    if (xmlOutput != null && xmlOutput.equals("true")) {
                        outputXML(resp, argSet);
                    } else {
                        resp.setContentType("text/html");
                        form.renderOutput(out, argSet);
                        cmsReq.setStatus(ICMSRequest.SUCCESS);
                    }
                }
            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);

                // NOTE:  The signed audit events
                //        LOGGING_SIGNED_AUDIT_CRL_RETRIEVAL and
                //        LOGGING_SIGNED_AUDIT_CRL_VALIDATION have
                //        already been logged at this point!

                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
            }
        } catch (EBaseException eAudit1) {
            if (!CRLFetched) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditCRLNum);

                audit(auditMessage);
            } else {
                if (!CRLValidated) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.CRL_VALIDATION,
                            auditSubjectID,
                            ILogger.FAILURE);

                    audit(auditMessage);
                }
            }
            throw eAudit1;
        }
        if (statsSub != null) {
            statsSub.endTiming("add_crl");
        }
    }

    public X509CRLImpl mapCRL1(String mime64)
            throws IOException {
        mime64 = Cert.stripCRLBrackets(mime64.trim());

        byte rawPub[] = Utils.base64decode(mime64);
        X509CRLImpl crl = null;

        try {
            crl = new X509CRLImpl(rawPub, false);
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
        return crl;
    }
}

class UpdateCRLThread extends Thread {
    private IDefStore mDefStore = null;
    private X509CRL mCRL = null;

    public UpdateCRLThread(
            IDefStore defStore, X509CRL crl) {
        mDefStore = defStore;
        mCRL = crl;
    }

    @Override
    public void run() {
        try {
            if (!((X509CRLImpl) mCRL).areEntriesIncluded())
                mCRL = new X509CRLImpl(((X509CRLImpl) mCRL).getEncoded());
            mDefStore.updateCRL(mCRL);
        } catch (CRLException e) {
        } catch (X509ExtensionException e) {
        } catch (EBaseException e) {
            // ignore
        }
    }
}
