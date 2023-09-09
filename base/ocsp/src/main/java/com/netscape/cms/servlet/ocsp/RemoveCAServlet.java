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
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ocsp.OCSPEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.OCSPRemoveCARequestEvent;
import com.netscape.certsrv.logging.event.OCSPRemoveCARequestProcessedEvent;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.ocsp.OCSPAuthority;

/**
 * Configure the CA to no longer respond to OCSP requests for a CA
 */
@WebServlet(
        name = "ocspRemoveCA",
        urlPatterns = "/agent/ocsp/removeCA",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="interface",     value="agent"),
                @WebInitParam(name="authority",     value="ocsp"),
                @WebInitParam(name="ID",            value="ocspRemoveCA"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",    value="certServer.ocsp.ca"),
                @WebInitParam(name="templatePath",  value="/agent/ocsp/removeCA.template")
        }
)
public class RemoveCAServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RemoveCAServlet.class);
    private static final long serialVersionUID = -4519898238552366358L;
    private final static String TPL_FILE = "removeCA.template";
    private String mFormPath = null;
    private OCSPAuthority mOCSPAuthority;

    public RemoveCAServlet() {
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

        mFormPath = "/ocsp/" + TPL_FILE;
        mTemplates.remove(CMSRequest.SUCCESS);

        OCSPEngine engine = OCSPEngine.getInstance();
        mOCSPAuthority = engine.getOCSP();

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param ca id. The format is string.
     * <li>signed.audit LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST used when a CA is attempted to be removed from the
     * OCSP responder
     * <li>signed.audit LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED is used when a remove CA request to the OCSP
     * Responder is processed successfully or not.
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "add");
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
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        if (auditSubjectID.equals(ILogger.NONROLEUSER) ||
                auditSubjectID.equals(ILogger.UNIDENTIFIED)) {
            String uid = authToken.getInString(AuthToken.USER_ID);
            if (uid != null) {
                logger.debug("RemoveCAServlet: auditSubjectID set to " + uid);
                auditSubjectID = uid;
            }
        }

        String caID = cmsReq.getHttpReq().getParameter("caID");

        if (caID == null) {

            auditor.log(OCSPRemoveCARequestEvent.createFailureEvent(
                    auditSubjectID));

            throw new ECMSGWException(CMS.getUserMessage(getLocale(req), "CMS_GW_MISSING_CA_ID"));
        }

        auditor.log(OCSPRemoveCARequestEvent.createSuccessEvent(
                auditSubjectID,
                caID));

        IDefStore defStore = mOCSPAuthority.getDefaultStore();

        try {
            defStore.deleteCRLIssuingPointRecord(caID);

        } catch (EBaseException e) {

            auditor.log(OCSPRemoveCARequestProcessedEvent.createFailureEvent(
                    auditSubjectID,
                    caID));

            logger.error("RemoveCAServlet:Error deleting CRL IssuingPoint: " + caID + ": " + e.getMessage(), e);
            throw new EBaseException(e.toString());
        }

        logger.debug("RemoveCAServlet::process: CRL IssuingPoint for CA successfully removed: " + caID);

        auditor.log(OCSPRemoveCARequestProcessedEvent.createSuccessEvent(
                auditSubjectID,
                caID));

        try {
            ServletOutputStream out = resp.getOutputStream();

            String xmlOutput = req.getParameter("xml");
            if (xmlOutput != null && xmlOutput.equals("true")) {
                outputXML(resp, argSet);
            } else {
                resp.setContentType("text/html");
                form.renderOutput(out, argSet);
                cmsReq.setStatus(CMSRequest.SUCCESS);
            }
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
    }
}
