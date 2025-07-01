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
import java.util.Locale;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzException;
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
 * Display a Specific Key Archival Request, and initiate
 * key recovery process
 */
@WebServlet(
        name = "kraKRADisplayBySerialForRecovery",
        urlPatterns = "/agent/kra/displayBySerialForRecovery",
        initParams = {
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="kra"),
                @WebInitParam(name="templatePath",  value="/agent/kra/displayBySerialForRecovery.template"),
                @WebInitParam(name="ID",            value="kraKRADisplayBySerialForRecovery"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="resourceID",    value="certServer.kra.key")
        }
)
public class DisplayBySerialForRecovery extends CMSServlet {

    private static final long serialVersionUID = 6876016034084761827L;
    private final static String INFO = "displayBySerial";
    private final static String TPL_FILE = "displayBySerialForRecovery.template";

    private final static String IN_SERIALNO = "serialNumber";
    private final static String OUT_OP = "op";
    private final static String OUT_SERVICE_URL = "serviceURL";
    private final static String OUT_ERROR = "errorDetails";

    private KeyRepository mKeyDB;
    private String mFormPath = null;
    private KeyRecoveryAuthority mService;

    /**
     * Constructor
     */
    public DisplayBySerialForRecovery() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "displayBySerialForRecovery.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/agent/kra/" + TPL_FILE;
        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = engine.getKRA();
        mKeyDB = engine.getKeyRepository();
        mService = kra;

        mTemplates.remove(CMSRequest.SUCCESS);
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
     * <li>http.param serialNumber request ID of key archival request
     * <li>http.param publicKeyData
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

        // Note that we should try to handle all the exceptions
        // instead of passing it up back to the servlet
        // framework.

        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        BigInteger seqNum = BigInteger.ZERO;

        try {
            if (req.getParameter(IN_SERIALNO) != null) {
                seqNum = new BigInteger(req.getParameter(IN_SERIALNO));
            }
            process(header, req.getParameter("publicKeyData"),
                    seqNum, req, locale[0], authToken);

        } catch (EAuthzException e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;

        } catch (NumberFormatException e) {
            header.addStringValue(OUT_ERROR,
                    CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (Exception e) {
            logger.warn("DisplayBySerialForRecovery: " + e.getMessage(), e);
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
    }

    /**
     * Display information about a particular key.
     * @throws EAuthzException
     */
    private synchronized void process(ArgBlock header, String publicKeyData,
            BigInteger seq, HttpServletRequest req,
            Locale locale, AuthToken authToken) throws EAuthzException {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig cs = engine.getConfig();

        try {
            header.addIntegerValue("noOfRequiredAgents",
                    mService.getNoOfRequiredAgents());
            header.addStringValue(OUT_OP,
                    req.getParameter(OUT_OP));
            header.addStringValue("keySplitting", cs.getString("kra.keySplitting"));
            header.addStringValue(OUT_SERVICE_URL,
                    req.getRequestURI());
            if (publicKeyData != null) {
                header.addStringValue("publicKeyData",
                        publicKeyData);
            }
            KeyRecord rec = mKeyDB.readKeyRecord(seq);
            mAuthz.checkRealm(rec.getRealm(), authToken, rec.getOwnerName(),
                    mAuthzResourceName, "read");
            KeyRecordParser.fillRecordIntoArg(rec, header);

            // recovery identifier
            header.addStringValue("recoveryID", mService.getRecoveryID());
        } catch (EAuthzException e) {
            throw e;
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale));
        }
    }
}
