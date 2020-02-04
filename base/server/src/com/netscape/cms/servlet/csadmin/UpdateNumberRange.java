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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.repository.IRepository;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.xml.XMLObject;

public abstract class UpdateNumberRange extends CMSServlet {

    public final static Logger logger = LoggerFactory.getLogger(UpdateNumberRange.class);

    private final static String SUCCESS = "0";
    private final static String AUTH_FAILURE = "2";

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

        CMSEngine engine = CMS.getCMSEngine();

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        logger.info("UpdateNumberRange: Authenticating request");
        IAuthToken authToken = authenticate(cmsReq);

        if (authToken == null) {
            logger.error("UpdateNumberRange: Authentication failed");
            outputError(httpResp, AUTH_FAILURE,
                    "Error: Authentication failed",
                    null);
            return;
        }

        logger.info("UpdateNumberRange: Authorizing request");
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
            logger.info("UpdateNumberRange: Type: " + type);

            EngineConfig cs = engine.getConfig();
            DatabaseConfig dbConfig = cs.getDatabaseConfig();
            String cstype = cs.getType();

            auditParams += "+type;;" + type;

            logger.info("UpdateNumberRange: Getting " + type + " repository");
            IRepository repo = getRepository(type);

            // checkRanges for replicaID - we do this each time a replica is created.
            // This needs to be done beforehand to ensure that we always have enough
            // replica numbers
            if (type.equals("replicaId")) {
                logger.debug("UpdateNumberRange: Checking replica number ranges");
                repo.checkRanges();
            }

            int radix = 10;
            String endNumConfig = null;
            String cloneNumConfig = null;
            String nextEndConfig = null;

            if (type.equals("request")) {
                radix = 10;
                endNumConfig = "endRequestNumber";
                cloneNumConfig = "requestCloneTransferNumber";
                nextEndConfig = "nextEndRequestNumber";

            } else if (type.equals("serialNo")) {
                radix = 16;
                endNumConfig = "endSerialNumber";
                cloneNumConfig = "serialCloneTransferNumber";
                nextEndConfig = "nextEndSerialNumber";

            } else if (type.equals("replicaId")) {
                radix = 10;
                endNumConfig = "endReplicaNumber";
                cloneNumConfig = "replicaCloneTransferNumber";
                nextEndConfig = "nextEndReplicaNumber";
            }

            /* UpdateNumberRange transfers a portion of this instance's
             * number range to a clone.
             *
             * Each number range has a "current range" which is the range
             * from which numbers are actively being consumed, and under
             * normal circumstances, a "next range" which is reserved for
             * this instance.  The next range is not necessarily adjacent to
             * the current range.  When the current range is depleted, the
             * instance switches to the next range and subsequently should
             * reserve a new range to become the new next range.  (In most
             * cases this is done by a scheduled task).
             */

            String endNumStr = dbConfig.getString(endNumConfig);
            BigInteger endNum = new BigInteger(endNumStr, radix);
            logger.info("UpdateNumberRange: dbs." + endNumConfig + ": " + endNum);

            String transferSizeStr = dbConfig.getString(cloneNumConfig, "");
            BigInteger transferSize = new BigInteger(transferSizeStr, radix);
            logger.info("UpdateNumberRange: dbs." + cloneNumConfig + ": " + transferSize);

            // transferred range will start at beginNum
            //  (which, for now, is just a candidate)
            BigInteger beginNum = endNum.subtract(transferSize).add(BigInteger.ONE);
            logger.info("UpdateNumberRange: Begin number: " + beginNum);

            /* We need to synchronise on repo because we peek the next
             * serial number, then set the max serial of the current or
             * next range.  If we don't synchronize, we could end up
             * using serial numbers that were transferred.
             */
            synchronized (repo) {

                // peek at the next serial number
                BigInteger nextSerial = repo.peekNextSerialNumber();
                if (nextSerial == null) {
                    String msg = "Current range depleted but no next range available.";
                    logger.error(msg);
                    throw new RuntimeException(msg); // will be caught below
                }

                logger.info("Configured transfer size: " + transferSize);
                logger.info("UpdateNumberRange: Current range: " + nextSerial + ".." + endNum);
                logger.info("UpdateNumberRange: Size: " + endNum.subtract(nextSerial).add(BigInteger.ONE));

                if (beginNum.compareTo(nextSerial) < 0) {
                    /* beginNum = the start of the range to transfer.
                     * nextSerial = the next number that would given out.
                     *
                     * If beginNum < nextSerial, then the remaining range is
                     * less than the transfer size.  Therefore we transfer from
                     * the end of the next range.
                     *
                     * If beginNum = nextSerial, then the remaining range is
                     * equal to the transfer size, and delegating it will fully
                     * deplete it.  We allow this to occur because:
                     *
                     * - a subsequent call to repo.getNextSerialNumber() will
                     *   perform a range check and switch to the next range.
                     * - a subsequent UpdateNumberRange will invoke
                     *   peekNextSerialNumber(), which will correctly return a
                     *   number from the next range.
                     *
                     * It is assumed that the _next range_ will not be depleted
                     * by repeated invocations of UpdateNumberRange, and that
                     * the current range will not be depleted in the duration
                     * between switching ranges (which extinguishes the next
                     * range) and reserving a new next range (performed by
                     * scheduled task).  This is unlikely but not guaranteed.
                     * The scheduled tasks check the size of the remaining range
                     * (|current| + |next|) and reserve a new range if it falls
                     * below the "low water mark".  As long as the low water
                     * mark is an adequate multiple of the clone transfer size,
                     * this scenario is unlikely to arise.  Furthermore,
                     * recovery is automatic thanks to the scheduled tasks.
                     */
                    endNum = new BigInteger(dbConfig.getString(nextEndConfig, ""), radix);
                    BigInteger newEndNum = endNum.subtract(transferSize);

                    logger.info("UpdateNumberRange: Transferring from the end of next range");
                    logger.info("UpdateNumberRange:   Next range current end: " + endNum);
                    logger.info("UpdateNumberRange:   Next range new end: " + newEndNum);

                    repo.setNextMaxSerial(newEndNum.toString(radix));
                    dbConfig.putString(nextEndConfig, newEndNum.toString(radix));
                    beginNum = newEndNum.add(BigInteger.ONE);

                } else {

                    logger.info("UpdateNumberRange: Transferring from the end of the current range");

                    BigInteger newEndNum = beginNum.subtract(BigInteger.ONE);
                    String newValStr = newEndNum.toString(radix);
                    repo.setMaxSerial(newEndNum.toString(radix));
                    dbConfig.putString(endNumConfig, newValStr);

                    logger.info("UpdateNumberRange: New current range: " + nextSerial + ".." + newEndNum);
                }

                logger.info("UpdateNumberRange: Transferring range: " + beginNum + ".." + endNum);
            }

            if (beginNum == null) {
                logger.error("UpdateNumberRange: Missing begin number");
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

    public abstract IRepository getRepository(String type) throws EBaseException;

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
