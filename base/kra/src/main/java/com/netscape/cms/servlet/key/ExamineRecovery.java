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
package com.netscape.cms.servlet.key;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;
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
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * View the Key Recovery Request
 */
@WebServlet(
        name = "kraKRAExamineRecovery",
        urlPatterns = "/agent/kra/examineRecovery",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="kra"),
                @WebInitParam(name="interface",     value="agent"),
                @WebInitParam(name="templatePath",  value="/agent/kra/examineRecovery.template"),
                @WebInitParam(name="ID",            value="kraKRAExamineRecovery"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",    value="certServer.kra.key")
        }
)
public class ExamineRecovery extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -953282265332774966L;
    private final static String INFO = "examineRecovery";
    private final static String TPL_FILE = "examineRecovery.template";

    private final static String OUT_OP = "op";
    private final static String OUT_SERVICE_URL = "serviceURL";

    private KeyRecoveryAuthority mService;
    private String mFormPath = null;

    /**
     * Constructs EA servlet.
     */
    public ExamineRecovery() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        KRAEngine engine = KRAEngine.getInstance();
        mService = engine.getKRA();
        mFormPath = "/kra/" + TPL_FILE;

        mTemplates.remove(CMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param recoveryID recovery request ID
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

        EBaseException error = null;

        try {
            process(header, req.getParameter("recoveryID"), req);
        } catch (EBaseException e) {
            error = e;
        } catch (Exception e) {
            error = new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        }

        /*
         catch (NumberFormatException e) {
         error = eBaseException(

         header.addStringValue(OUT_ERROR,
         MessageFormatter.getLocalizedString(
         locale[0],
         BaseResources.class.getName(),
         BaseResources.INTERNAL_ERROR_1,
         e.toString()));
         }
         */

        try {
            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                    outputXML(resp, argSet);
                } else {
                    ServletOutputStream out = resp.getOutputStream();
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

    /**
     * Recovers a key. The p12 will be protected by the password
     * provided by the administrator.
     */
    private void process(ArgBlock header, String recoveryID, HttpServletRequest req) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

        try {
            header.addStringValue(OUT_OP,
                    req.getParameter(OUT_OP));
            header.addStringValue(OUT_SERVICE_URL,
                    req.getRequestURI());
            header.addStringValue("keySplitting", cs.getString("kra.keySplitting"));
            Hashtable<String, Object> params = mService.getRecoveryParams(
                    recoveryID);

            if (params == null) {
                logger.error(CMS.getLogMessage("CMSGW_NO_RECOVERY_TOKEN_FOUND_1", recoveryID));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_RECOVERY_TOKEN_FOUND", recoveryID));
            }
            String keyID = (String) params.get("keyID");
            header.addStringValue("serialNumber", keyID);
            header.addStringValue("recoveryID", recoveryID);

            KeyRepository mKeyDB = engine.getKeyRepository();
            KeyRecord rec = mKeyDB.readKeyRecord(new
                    BigInteger(keyID));
            KeyRecordParser.fillRecordIntoArg(rec, header);

        } catch (EBaseException e) {
            logger.error("ExamineRecovery: " + e.getMessage(), e);
            throw e;
        }

        /*
         catch (Exception e) {
         header.addStringValue(OUT_ERROR, e.toString());
         }
         */
    }
}
