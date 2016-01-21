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
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.mapping.BaseMappingResolver;
import org.dogtagpki.server.tps.mapping.FilterMappingParams;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.tps.token.TokenStatus;

public class TPSPinResetProcessor extends TPSProcessor {

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
        CMS.debug(method + ": entering...");

        String logMsg = null;
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);

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
            tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw e;
        }
        appletInfo.setAid(getCardManagerAID());

        tokenRecord = isTokenRecordPresent(appletInfo);

        if (tokenRecord == null) {
            //We can't reset the pin of a token that does not exist.
            logMsg = "Token does not exist!";
            auditPinReset(session.getIpAddress(), userid, appletInfo, "failure", null, logMsg);
            CMS.debug(method + ": " + logMsg);
            throw new TPSException(method + logMsg +
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);
        }

        TokenStatus status = tokenRecord.getTokenStatus();

        CMS.debug(method + ": Token status: " + status);

        if (!status.equals(TokenStatus.ACTIVE)) {
            throw new TPSException(method + " Attempt to reset pin of token not currently active!",
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);

        }

        session.setTokenRecord(tokenRecord);

        String tokenType = null;

        try {
            String resolverInstName = getResolverInstanceName();

            if (!resolverInstName.equals("none") && (selectedTokenType == null)) {
                FilterMappingParams mappingParams = createFilterMappingParams(resolverInstName,
                        appletInfo.getCUIDhexStringPlain(), appletInfo.getMSNString(),
                        appletInfo.getMajorVersion(), appletInfo.getMinorVersion());
                TPSSubsystem subsystem =
                        (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
                BaseMappingResolver resolverInst =
                        subsystem.getMappingResolverManager().getResolverInstance(resolverInstName);
                tokenType = resolverInst.getResolvedMapping(mappingParams);
                setSelectedTokenType(tokenType);
                CMS.debug(method + " resolved tokenType: " + tokenType);
            }
        } catch (TPSException e) {
            logMsg = e.toString();
            auditPinReset(session.getIpAddress(), userid, appletInfo, "failure", null, logMsg);
            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        statusUpdate(15, "PROGRESS_PIN_RESET_RESOLVE_PROFILE");

        checkProfileStateOK();

        checkAndAuthenticateUser(appletInfo, tokenType);

        checkAndUpgradeApplet(appletInfo);
        appletInfo = getAppletInfo();

        //Check and upgrade keys if called for

        SecureChannel channel = checkAndUpgradeSymKeys(appletInfo, tokenRecord);
        channel.externalAuthenticate();

        checkAndHandlePinReset(channel);

        auditPinReset(session.getIpAddress(), userid, appletInfo, "success",
                channel.getKeyInfoData().toHexStringPlain(), null);

        try {
            tps.tdb.tdbUpdateTokenEntry(tokenRecord);
            CMS.debug(method + ": token record updated!");
        } catch (Exception e) {
            String failMsg = "update token failure";
            logMsg = failMsg + ":" + e.toString();
            tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
            throw new TPSException(logMsg);
        }

        statusUpdate(100, "PROGRESS_PIN_RESET_COMPLETE");

        logMsg = "pin reset operation completed successfully";
        tps.tdb.tdbActivity(ActivityDatabase.OP_PIN_RESET, tokenRecord, session.getIpAddress(), logMsg,
                "success");

        CMS.debug(method + ": Token Pin successfully reset!");

    }

    protected void auditPinReset(String ip, String subjectID,
            AppletInfo aInfo,
            String status,
            String keyVersion,
            String info) {

        String auditType = "";
        switch (status) {
        case "success":
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_PIN_RESET_SUCCESS_6";
            break;
        default:
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_PIN_RESET_FAILURE_6";
        }

        String auditMessage = CMS.getLogMessage(
                auditType,
                ip,
                subjectID,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                status,
                getSelectedTokenType(),
                keyVersion,
                info);
        audit(auditMessage);
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
