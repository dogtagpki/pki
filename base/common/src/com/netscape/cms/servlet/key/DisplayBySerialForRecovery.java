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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;
import com.netscape.certsrv.dbs.keydb.IKeyRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.kra.IKeyService;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Display a Specific Key Archival Request, and initiate
 * key recovery process
 *
 * @version $Revision$, $Date$
 */
public class DisplayBySerialForRecovery extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 6876016034084761827L;
    private final static String INFO = "displayBySerial";
    private final static String TPL_FILE = "displayBySerialForRecovery.template";

    private final static String IN_SERIALNO = "serialNumber";
    private final static String OUT_OP = "op";
    private final static String OUT_SERVICE_URL = "serviceURL";
    private final static String OUT_ERROR = "errorDetails";

    private IKeyRepository mKeyDB = null;
    private String mFormPath = null;
    private IKeyService mService = null;

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
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/agent/" + mAuthority.getId() + "/" + TPL_FILE;
        mKeyDB = ((IKeyRecoveryAuthority) mAuthority).getKeyRepository();
        mService = (IKeyService) mAuthority;

        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Returns serlvet information.
     */
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

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        // Note that we should try to handle all the exceptions
        // instead of passing it up back to the servlet
        // framework.

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        BigInteger seqNum = BigInteger.ZERO;

        try {
            if (req.getParameter(IN_SERIALNO) != null) {
                seqNum = new BigInteger(req.getParameter(IN_SERIALNO));
            }
            process(argSet, header,
                    req.getParameter("publicKeyData"),
                    seqNum, req, resp, locale[0]);
        } catch (NumberFormatException e) {
            header.addStringValue(OUT_ERROR,
                    CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.toString());
        }
        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
    }

    /**
     * Display information about a particular key.
     */
    private synchronized void process(CMSTemplateParams argSet,
            IArgBlock header, String publicKeyData, BigInteger seq,
            HttpServletRequest req, HttpServletResponse resp,
            Locale locale) {
        try {
            header.addIntegerValue("noOfRequiredAgents",
                    mService.getNoOfRequiredAgents());
            header.addStringValue(OUT_OP,
                    req.getParameter(OUT_OP));
            header.addStringValue("keySplitting",
                    CMS.getConfigStore().getString("kra.keySplitting"));
            header.addStringValue(OUT_SERVICE_URL,
                    req.getRequestURI());
            if (publicKeyData != null) {
                header.addStringValue("publicKeyData",
                        publicKeyData);
            }
            IKeyRecord rec = mKeyDB.readKeyRecord(seq);

            KeyRecordParser.fillRecordIntoArg(rec, header);

            // recovery identifier
            header.addStringValue("recoveryID", mService.getRecoveryID());
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale));
        }
    }
}
