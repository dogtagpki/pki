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
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.util.Cert;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.OCSPAddCARequestEvent;
import com.netscape.certsrv.logging.event.OCSPAddCARequestProcessedEvent;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.ocsp.OCSPAuthority;

/**
 * Configure the CA to respond to OCSP requests for a CA
 *
 * @version $Revision$ $Date$
 */
public class AddCAServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AddCAServlet.class);
    private static final long serialVersionUID = 1065151608542115340L;

    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);

    private final static String TPL_FILE = "addCA.template";
    private String mFormPath = null;
    private OCSPAuthority mOCSPAuthority;

    public AddCAServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "addCA.template" to process the response.
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
     * <ul>
     * <li>http.param cert ca certificate. The format is base-64, DER encoded, wrapped with -----BEGIN CERTIFICATE-----,
     * -----END CERTIFICATE----- strings
     * <li>signed.audit LOGGING_SIGNED_AUDIT_OCSP_ADD_CA_REQUEST used when a CA is attempted to be added to the OCSP
     * responder
     * <li>signed.audit LOGGING_SIGNED_AUDIT_OCSP_ADD_CA_REQUEST_PROCESSED used when an add CA request to the OCSP
     * Responder is processed
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();
        String auditSubjectID = auditSubjectID();
        String auditCA = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String auditCASubjectDN = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

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
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        if (auditSubjectID.equals(ILogger.NONROLEUSER) ||
                auditSubjectID.equals(ILogger.UNIDENTIFIED)) {
            String uid = authToken.getInString(IAuthToken.USER_ID);
            if (uid != null) {
                logger.debug("AddCAServlet: auditSubjectID set to " + uid);
                auditSubjectID = uid;
            }
        }
        String b64 = cmsReq.getHttpReq().getParameter("cert");

        if (b64 == null) {

            audit(OCSPAddCARequestEvent.createFailureEvent(
                    auditSubjectID));

            throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CA_CERT"));
        }

        auditCA = Cert.normalizeCertStr(Cert.stripCertBrackets(b64.trim()));

        audit(OCSPAddCARequestEvent.createSuccessEvent(
                auditSubjectID,
                auditCA));

        if (b64.indexOf(Cert.HEADER) == -1) {

            audit(OCSPAddCARequestProcessedEvent.createFailureEvent(
                    auditSubjectID,
                    auditCASubjectDN));

            throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CERT_HEADER"));
        }
        if (b64.indexOf(Cert.FOOTER) == -1) {

            audit(OCSPAddCARequestProcessedEvent.createFailureEvent(
                    auditSubjectID,
                    auditCASubjectDN));

            throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CERT_FOOTER"));
        }

        IDefStore defStore = mOCSPAuthority.getDefaultStore();

        X509Certificate leafCert = null;
        X509Certificate certs[] = null;

        try {
            X509Certificate cert = Cert.mapCert(b64);

            if (cert == null) {
                logger.warn("AddCAServlet::process() - cert is null!");

                audit(OCSPAddCARequestProcessedEvent.createFailureEvent(
                        auditSubjectID,
                        auditCASubjectDN));

                throw new EBaseException("cert is null");
            } else {
                certs = new X509Certificate[1];
            }

            certs[0] = cert;
            leafCert = cert;
            auditCASubjectDN = leafCert.getSubjectDN().getName();
        } catch (Exception e) {
        }
        if (certs == null) {
            try {
                // this could be a chain
                certs = Cert.mapCertFromPKCS7(b64);
                if (certs[0].getSubjectDN().getName().equals(certs[0].getIssuerDN().getName())) {
                    leafCert = certs[certs.length - 1];
                } else {
                    leafCert = certs[0];
                }
                auditCASubjectDN = leafCert.getSubjectDN().getName();
            } catch (Exception e) {

                audit(OCSPAddCARequestProcessedEvent.createFailureEvent(
                        auditSubjectID,
                        auditCASubjectDN));

                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_ENCODING_CA_CHAIN_ERROR"));
            }
        }
        if (certs != null && certs.length > 0) {
            // (1) need to normalize (sort) the chain

            // (2) store certificate (and certificate chain) into
            // database
            ICRLIssuingPointRecord rec = defStore.createCRLIssuingPointRecord(
                    leafCert.getSubjectDN().getName(),
                    BIG_ZERO,
                    MINUS_ONE, null, null);

            try {
                rec.set(ICRLIssuingPointRecord.ATTR_CA_CERT, leafCert.getEncoded());
            } catch (Exception e) {

                audit(OCSPAddCARequestProcessedEvent.createFailureEvent(
                        auditSubjectID,
                        auditCASubjectDN));

                // error
            }
            defStore.addCRLIssuingPoint(leafCert.getSubjectDN().getName(), rec);
            logger.info("Added CA certificate " + leafCert.getSubjectDN().getName());

            audit(OCSPAddCARequestProcessedEvent.createSuccessEvent(
                    auditSubjectID,
                    auditCASubjectDN));
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            String xmlOutput = req.getParameter("xml");
            if (xmlOutput != null && xmlOutput.equals("true")) {
                outputXML(resp, argSet);
            } else {
                resp.setContentType("text/html");
                form.renderOutput(out, argSet);
                cmsReq.setStatus(ICMSRequest.SUCCESS);
            }
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
    }
}
