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
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.repository.IRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.xml.XMLObject;

public class UpdateNumberRange extends CMSServlet {

    public final static Logger logger = LoggerFactory.getLogger(UpdateNumberRange.class);

    private static final long serialVersionUID = -1584171713024263331L;
    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

    public UpdateNumberRange() {
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        logger.debug("UpdateNumberRange: initializing...");
        super.init(sc);
        logger.debug("UpdateNumberRange: done initializing...");
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param op 'downloadBIN' - return the binary certificate chain
     * <li>http.param op 'displayIND' - display pretty-print of certificate chain components
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        logger.debug("UpdateNumberRange: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        logger.debug("UpdateNumberRange process: authentication starts");

        IAuthToken authToken = authenticate(cmsReq);

        if (authToken == null) {
            logger.error("UpdateNumberRange: Authentication failed");
            outputError(httpResp, AUTH_FAILURE,
                    "Error: Authentication failed",
                    null);
            return;
        }

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken, mAuthzResourceName,
                    "modify");
        } catch (Exception e) {
            logger.error("UpdateNumberRange: Authorization failed: " + e.getMessage(), e);
            outputError(httpResp, "Error: Authorization failed");
            return;
        }

        if (authzToken == null) {
            logger.error("UpdateNumberRange: Authorization failed");
            outputError(httpResp, "Error: Authorization failed");
            return;
        }

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditParams = "source;;updateNumberRange";

        try {
            String type = httpReq.getParameter("type");
            logger.debug("UpdateNumberRange: type: " + type);

            IConfigStore cs = CMS.getConfigStore();
            String cstype = cs.getString("cs.type", "");

            auditParams += "+type;;" + type;

            BigInteger beginNum = null;
            BigInteger endNum = null;
            BigInteger oneNum = new BigInteger("1");
            String endNumConfig = null;
            String cloneNumConfig = null;
            String nextEndConfig = null;
            int radix = 10;

            IRepository repo = null;
            if (cstype.equals("KRA")) {
                IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) CMS.getSubsystem(
                        IKeyRecoveryAuthority.ID);
                if (type.equals("request")) {
                    repo = kra.getRequestQueue().getRequestRepository();
                } else if (type.equals("serialNo")) {
                    repo = kra.getKeyRepository();
                } else if (type.equals("replicaId")) {
                    repo = kra.getReplicaRepository();
                }

            } else { // CA
                ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(
                        ICertificateAuthority.ID);
                if (type.equals("request")) {
                    repo = ca.getRequestQueue().getRequestRepository();
                } else if (type.equals("serialNo")) {
                    repo = ca.getCertificateRepository();
                } else if (type.equals("replicaId")) {
                    repo = ca.getReplicaRepository();
                }
            }

            // checkRanges for replicaID - we do this each time a replica is created.
            // This needs to be done beforehand to ensure that we always have enough
            // replica numbers
            if (type.equals("replicaId")) {
                logger.debug("UpdateNumberRange: Checking replica number ranges");
                repo.checkRanges();
            }

            if (type.equals("request")) {
                radix = 10;
                endNumConfig = "dbs.endRequestNumber";
                cloneNumConfig = "dbs.requestCloneTransferNumber";
                nextEndConfig = "dbs.nextEndRequestNumber";
            } else if (type.equals("serialNo")) {
                radix = 16;
                endNumConfig = "dbs.endSerialNumber";
                cloneNumConfig = "dbs.serialCloneTransferNumber";
                nextEndConfig = "dbs.nextEndSerialNumber";
            } else if (type.equals("replicaId")) {
                radix = 10;
                endNumConfig = "dbs.endReplicaNumber";
                cloneNumConfig = "dbs.replicaCloneTransferNumber";
                nextEndConfig = "dbs.nextEndReplicaNumber";
            }

            String endNumStr = cs.getString(endNumConfig);
            endNum = new BigInteger(endNumStr, radix);
            logger.debug("UpdateNumberRange: " + endNumConfig + ": " + endNum);

            String decrementStr = cs.getString(cloneNumConfig);
            BigInteger decrement = new BigInteger(decrementStr, radix);
            logger.debug("UpdateNumberRange: " + cloneNumConfig + ": " + decrement);

            beginNum = endNum.subtract(decrement).add(oneNum);
            logger.debug("UpdateNumberRange: beginNum: " + beginNum);

            if (beginNum.compareTo(repo.peekNextSerialNumber()) < 0) {

                logger.debug("UpdateNumberRange: Transferring from the end of on-deck range");

                String nextEndNumStr = cs.getString(nextEndConfig);
                BigInteger endNum2 = new BigInteger(nextEndNumStr, radix);
                logger.debug("UpdateNumberRange: " + nextEndConfig + ": " + endNum2);

                String newValStr = endNum2.subtract(decrement).toString(radix);
                logger.debug("UpdateNumberRange: nextMaxSerial: " + newValStr);

                repo.setNextMaxSerial(newValStr);

                cs.putString(nextEndConfig, newValStr);
                beginNum = endNum2.subtract(decrement).add(oneNum);
                endNum = endNum2;

            } else {

                logger.debug("UpdateNumberRange: Transferring from the end of the current range");

                String newValStr = beginNum.subtract(oneNum).toString(radix);
                logger.debug("UpdateNumberRange: maxSerial: " + newValStr);

                repo.setMaxSerial(newValStr);
                cs.putString(endNumConfig, newValStr);
            }

            if (beginNum == null) {
                logger.error("UpdateNumberRange: Missing beginNum");
                auditMessage = CMS.getLogMessage(
                                   AuditEvent.CONFIG_SERIAL_NUMBER,
                                   auditSubjectID,
                                   ILogger.FAILURE,
                                   auditParams);
                audit(auditMessage);
                return;
            }

            // Enable serial number management in master for certs and requests
            if (type.equals("replicaId")) {
                repo.setEnableSerialMgmt(true);
            }

            // insert info
            logger.debug("UpdateNumberRange: Sending response");

            // send success status back to the requestor
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            xmlObj.addItemToContainer(root, "beginNumber", beginNum.toString(radix));
            xmlObj.addItemToContainer(root, "endNumber", endNum.toString(radix));
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
            cs.commit(false);

            auditParams += "+beginNumber;;" + beginNum.toString(radix) +
                          "+endNumber;;" + endNum.toString(radix);

            auditMessage = CMS.getLogMessage(
                               AuditEvent.CONFIG_SERIAL_NUMBER,
                               auditSubjectID,
                               ILogger.SUCCESS,
                               auditParams);
            audit(auditMessage);

        } catch (Exception e) {
            logger.error("UpdateNumberRange: Unable to update number range: " + e.getMessage(), e);

            auditMessage = CMS.getLogMessage(
                               AuditEvent.CONFIG_SERIAL_NUMBER,
                               auditSubjectID,
                               ILogger.FAILURE,
                               auditParams);
            audit(auditMessage);

            outputError(httpResp, "Error: Unable to update number range: " + e.getMessage());
        }
    }

    protected void setDefaultTemplates(ServletConfig sc) {
    }

    protected void renderTemplate(
            CMSRequest cmsReq, String templateName, ICMSTemplateFiller filler)
            throws IOException {// do nothing
    }

    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    /**
     * Retrieves locale based on the request.
     */
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                    UserInfo.getUserCountry(lang));
        }
        return locale;
    }
}
