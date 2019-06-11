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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.processor;

import java.io.IOException;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.TPSTokenPolicy;
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.mapping.BaseMappingResolver;
import org.dogtagpki.server.tps.mapping.FilterMappingParams;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.logging.event.TokenPinResetEvent;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

public class TPSPinResetProcessor extends TPSProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSPinResetProcessor.class);

    public TPSPinResetProcessor(TPSSession session) {
        super(session);
        // TODO Auto-generated constructor stub
    }

    @Override
    public void process(BeginOpMsg beginMsg) throws TPSException, IOException {
        if (beginMsg == null) {
            throw new TPSException("TPSPinResetProcessor.process: invalid input data, not beginMsg provided.",
                    TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }
        setBeginMessage(beginMsg);
        setCurrentTokenOperation(TPSEngine.PIN_RESET_OP);

        resetPin();

    }

    private void resetPin() throws TPSException, IOException {

        String method = "TPSPinResetProcessor.resetPin()";
        //ToDo: Implement full pin reset processor, the pin reset portion
        // of an enrollment works fine. We just need to finish this to perform
        // a completely stand alone pin reset of an already enrolled token.
        logger.debug(method + ": entering...");

        String logMsg = null;
        CMSEngine engine = CMS.getCMSEngine();
        TPSSubsystem tps = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);

        AppletInfo appletInfo = null;
        TokenRecord tokenRecord = null;

        statusUpdate(10, "PROGRESS_START_PIN_RESET");

        try {
            appletInfo = getAppletInfo();
            auditOpRequest("pinReset", appletInfo, "success", null);
        } catch (TPSException e) {
            logMsg = e.toString();
            // appletInfo is null as expected at this point
            // but audit for the record anyway
            auditOpRequest("pinReset", appletInfo, "failure", logMsg);
            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw e;
        }
        appletInfo.setAid(getCardManagerAID());

        tokenRecord = isTokenRecordPresent(appletInfo);

        if (tokenRecord == null) {
            //We can't reset the pin of a token that does not exist.
            logMsg = method + "Token does not exist!";
            auditPinResetFailure(session.getIpAddress(), userid, appletInfo, logMsg);

            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
            logger.error(logMsg);
            throw new TPSException(logMsg +
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);
        }

        TPSTokenPolicy tokenPolicy = new TPSTokenPolicy(tps);

        session.setTokenRecord(tokenRecord);

        String tokenType = null;

        try {
            String resolverInstName = getResolverInstanceName();

            if (!resolverInstName.equals("none") && (selectedTokenType == null)) {
                FilterMappingParams mappingParams = createFilterMappingParams(resolverInstName,
                        appletInfo.getCUIDhexStringPlain(), appletInfo.getMSNString(),
                        appletInfo.getMajorVersion(), appletInfo.getMinorVersion());
                TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
                BaseMappingResolver resolverInst =
                        subsystem.getMappingResolverManager().getResolverInstance(resolverInstName);
                tokenType = resolverInst.getResolvedMapping(mappingParams);
                setSelectedTokenType(tokenType);
                logger.debug(method + " resolved tokenType: " + tokenType);
            }
        } catch (TPSException e) {
            logMsg = e.toString();
            auditPinResetFailure(session.getIpAddress(), userid, appletInfo, logMsg);

            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        statusUpdate(15, "PROGRESS_PIN_RESET_RESOLVE_PROFILE");

        checkProfileStateOK();

        checkAndAuthenticateUser(appletInfo, tokenType);

        TokenStatus status = tokenRecord.getTokenStatus();

        logger.debug(method + ": Token status: " + status);

        if (!status.equals(TokenStatus.ACTIVE)) {
            logMsg = method + "Can not reset the pin of a non active token.";
            auditPinResetFailure(session.getIpAddress(), userid, appletInfo, logMsg);

            throw new TPSException(method + " Attempt to reset pin of token not currently active!",
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);

        }

        boolean pinResetAllowed = tokenPolicy.isAllowedPinReset(tokenRecord.getId());

        logger.debug(method + ": PinResetPolicy: Pin Reset Allowed:  " + pinResetAllowed);
        logMsg = method + " PinReset Policy forbids pin reset operation.";
        if (pinResetAllowed == false) {
            auditPinResetFailure(session.getIpAddress(), userid, appletInfo, logMsg);

            throw new TPSException(method + " Attempt to reset pin when token policy disallows it.!",
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);

        }

        checkAndUpgradeApplet(appletInfo);
        appletInfo = getAppletInfo();

        //Check and upgrade keys if called for

        SecureChannel channel = checkAndUpgradeSymKeys(appletInfo, tokenRecord);
        channel.externalAuthenticate();

        checkAndHandlePinReset(channel);

        auditPinResetSuccess(session.getIpAddress(), userid, appletInfo,
                channel.getKeyInfoData().toHexStringPlain());

        statusUpdate(100, "PROGRESS_PIN_RESET_COMPLETE");
        logMsg = "update token during pin reset";
        try {
            tps.tdb.tdbUpdateTokenEntry(tokenRecord);
            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg, "success");
            logger.debug(method + ": token record updated!");
        } catch (Exception e) {
            logMsg = logMsg + ":" + e.toString();
            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
            throw new TPSException(logMsg);
        }

        logger.debug(method + ": Token Pin successfully reset!");

    }

    protected void auditPinResetSuccess(String ip, String subjectID,
            AppletInfo aInfo,
            String keyVersion) {

        TokenPinResetEvent event = TokenPinResetEvent.success(
                ip,
                subjectID,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                getSelectedTokenType(),
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                keyVersion);

        signedAuditLogger.log(event);
    }

    protected void auditPinResetFailure(String ip, String subjectID,
            AppletInfo aInfo,
            String info) {

        TokenPinResetEvent event = TokenPinResetEvent.failure(
                ip,
                subjectID,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                getSelectedTokenType(),
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                info);

        signedAuditLogger.log(event);
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
