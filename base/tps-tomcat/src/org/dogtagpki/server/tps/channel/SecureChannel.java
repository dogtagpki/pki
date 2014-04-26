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
package org.dogtagpki.server.tps.channel;

import java.io.IOException;

import org.dogtagpki.server.tps.processor.TPSProcessor;
import org.dogtagpki.tps.apdu.APDU;
import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.apdu.DeleteFileAPDU;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU.SecurityLevel;
import org.dogtagpki.tps.apdu.InstallAppletAPDU;
import org.dogtagpki.tps.apdu.InstallLoadAPDU;
import org.dogtagpki.tps.apdu.LoadFileAPDU;
import org.dogtagpki.tps.apdu.SetIssuerInfoAPDU;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.EndOp.TPSStatus;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class SecureChannel {

    // Have not written all code to use all of these as of yet.

    private TPSProcessor processor;
    private PK11SymKey sessionKey;
    private PK11SymKey encSessionKey;
    private TPSBuffer drmDesKey;
    private TPSBuffer kekDesKey;
    private TPSBuffer keyCheck;
    private TPSBuffer keyDiversificationData;
    private TPSBuffer cardChallenge;
    private TPSBuffer cardCryptogram;
    private TPSBuffer hostChallenge;
    private TPSBuffer hostCryptogram;
    private TPSBuffer icv;
    private SecurityLevel secLevel;

    public SecureChannel(TPSProcessor processor, PK11SymKey sessionKey, PK11SymKey encSessionKey, TPSBuffer drmDesKey,
            TPSBuffer kekDesKey, TPSBuffer keyCheck, TPSBuffer keyDiversificationData, TPSBuffer cardChallenge,
            TPSBuffer cardCryptogram, TPSBuffer hostChallenge, TPSBuffer hostCryptogram) throws TPSException {

        if (processor == null || sessionKey == null | encSessionKey == null || keyDiversificationData == null
                || cardChallenge == null || cardCryptogram == null || hostChallenge == null || hostCryptogram == null) {
            throw new TPSException("SecureChannel.SecureChannel: Invalid data in constructor!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        this.processor = processor;
        this.sessionKey = sessionKey;
        this.encSessionKey = encSessionKey;
        this.drmDesKey = drmDesKey;
        this.kekDesKey = kekDesKey;
        this.keyCheck = keyCheck;
        this.keyDiversificationData = keyDiversificationData;
        this.cardChallenge = cardChallenge;
        this.cardCryptogram = cardCryptogram;
        this.hostChallenge = hostChallenge;
        this.hostCryptogram = hostCryptogram;
        this.icv = new TPSBuffer(8);

        this.secLevel = SecurityLevel.SECURE_MSG_MAC_ENC;
        //ToDo: Write method that reads this from the config

    }

    public static void main(String[] args) {
    }

    public void externalAuthenticate() throws TPSException, IOException {

        CMS.debug("SecureChannel.externalAuthenticate: entering.");

        ExternalAuthenticateAPDU externalAuth = new ExternalAuthenticateAPDU(hostCryptogram,
                secLevel);

        computeAPDUMac(externalAuth);

        APDUResponse response = processor.handleAPDURequest(externalAuth);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.eternalAuthenticate. Failed to external authenticate to token.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        CMS.debug("SecureChannel.externalAuthenticate: Successfully completed, exiting ...");

    }

    //This method computes the mac AND encryption if needed.
    private void computeAPDU(APDU apdu) throws TPSException {

        CMS.debug("SecureChannel.computeAPDU: entering..");

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDU: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        computeAPDUMac(apdu);

        if (secLevel == SecurityLevel.SECURE_MSG_MAC_ENC) {
            try {
                // CMS.debug("SecureChannel.computeAPDU: Before encryption data value: " + apdu.getData().toHexString());
                apdu.secureMessage(encSessionKey);
                // CMS.debug("SecureChannel.computeAPDU: After encryption data value: " + apdu.getData().toHexString());
            } catch (EBaseException e) {
                throw new TPSException("SecureChannel.computeAPDU: Can't encrypt outgoing data! " + e);
            }

            CMS.debug("SecureChannel.computeAPDU: Successfully encrypted apdu data.");
        }
    }

    // This method computes MAC only.
    private void computeAPDUMac(APDU apdu) throws TPSException {
        TPSBuffer newMac = null;
        TPSBuffer data = null;

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDUMac: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        data = apdu.getDataToMAC();

        CMS.debug("SecureChannel.computeAPDUMac: data To MAC: " + data.toHexString());

        try {
            newMac = Util.computeMAC(sessionKey, data, icv);
        } catch (EBaseException e) {
            CMS.debug("SecureChannel.compuatAPDUMac: Can't compute mac. " + e);
            throw new TPSException("SecureChannel.compuatAPDUMac: Can't compute mac.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        CMS.debug("SecureChannel.computeAPDUMac: computed MAC: " + newMac.toHexString());

        apdu.setMAC(newMac);

        icv.set(newMac);
    }

    public void deleteFileX(TPSBuffer aid) throws TPSException, IOException {
        CMS.debug("SecureChannel.deleteFileX: entering...");
        if (aid == null) {
            throw new TPSException("SecureChannel.deleteFileX: no input aid!");
        }

        DeleteFileAPDU deleteFile = new DeleteFileAPDU(aid);

        computeAPDU(deleteFile);

        processor.handleAPDURequest(deleteFile);

    }

    // Begin process of loading applet onto token.
    public void installLoad(TPSBuffer packageAID, TPSBuffer sdAID, int fileLength) throws TPSException, IOException {

        CMS.debug("SecureChannel.installLoad: entering ...");

        if (packageAID == null || sdAID == null || fileLength <= 0) {
            throw new TPSException("SecureChannel.insallLoad bad input parameters!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        InstallLoadAPDU install = new InstallLoadAPDU(packageAID, sdAID, fileLength);

        CMS.debug("SecureChannel.installLoad: Pre computed apdu: " + install.getEncoding().toHexString());

        computeAPDU(install);

        APDUResponse response = processor.handleAPDURequest(install);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.installLoad. Failed to perform installLoad operation.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

    }

    //Actually load applet file onto the token.

    public void loadFile(TPSBuffer programFile, int blockSize, int startProgress, int endProgress) throws TPSException,
            IOException {
        CMS.debug("SecureChannel.loadFile entering...");

        if (programFile == null || blockSize <= 0) {
            throw new TPSException("ScureChannel.loadFile. Bad input data.", TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        TPSBuffer length = null;

        TPSBuffer tag = new TPSBuffer(1, (byte) 0xC4);

        int progSize = programFile.size();

        if (progSize < 128) {
            length = new TPSBuffer(1, (byte) progSize);
        } else if (progSize <= 255) {
            length = new TPSBuffer(1, (byte) 0x81);
            length.add((byte) progSize);
        } else {
            length = new TPSBuffer(1, (byte) 0x82);
            length.add((byte) ((progSize >> 8) & 0xff));
            length.add((byte) (progSize & 0xff));

        }

        TPSBuffer tbsProgramFile = new TPSBuffer(tag);
        tbsProgramFile.add(length);
        tbsProgramFile.add(programFile);

        int totalLen = tbsProgramFile.size();
        int sizeToSend = totalLen;

        int finalBlockSize = 0;
        float progressBlockSize = 0;

        if (secLevel == SecurityLevel.SECURE_MSG_MAC_ENC) {
            // need leave room for possible encryption padding
            finalBlockSize = blockSize - 0x10;
        } else {
            finalBlockSize = blockSize - 8;
        }

        //rough number is good enough
        int numLoops = sizeToSend / blockSize;

        if (numLoops == 0) { // We have bogus data here. Good bye.
            throw new TPSException("SecureChannel.loadFile. Bad input data.", TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }
        progressBlockSize = (float) (endProgress - startProgress) / numLoops;

        int count = 0;
        byte refControl = 0x00;

        do {
            if (sizeToSend < finalBlockSize) {
                finalBlockSize = sizeToSend;
                refControl = (byte) 0x80;

            }

            CMS.debug("SecureChannel.loadFile: taking data substring from: " + (totalLen - sizeToSend) + " size: "
                    + finalBlockSize + " to: " + ((totalLen - sizeToSend) + finalBlockSize));

            TPSBuffer piece = tbsProgramFile.substr(totalLen - sizeToSend, finalBlockSize);

            CMS.debug("SecureChannel.loadFile: attempting to send piece: " + sizeToSend);

            loadFileSegment(refControl, count, piece);

            if (processor.requiresStatusUpdate()) {
                processor.statusUpdate(startProgress + (int) (count * progressBlockSize), "PROGRESS_APPLET_BLOCK");
            }

            sizeToSend -= finalBlockSize;

            count++;

        } while (sizeToSend > 0);

    }

    //Load one piece of the applet file onto the token.
    private void loadFileSegment(byte refControl, int count, TPSBuffer piece) throws TPSException, IOException {

        if (piece == null || count < 0) {
            throw new TPSException("SecureChannel.loadFileSegment: invalid input data.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        LoadFileAPDU loadFile = new LoadFileAPDU(refControl, (byte) count, piece);

        computeAPDU(loadFile);

        APDUResponse response = processor.handleAPDURequest(loadFile);

        if (!response.checkResult()) {
            throw new TPSException(
                    "SecureChannel.loadFileSegment. Failed to perform loadFileSegmentInstallLoad operation.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

    }

    // Kick off the applet loading process.
    public void installApplet(TPSBuffer netkeyPAIDBuff, TPSBuffer netkeyAIDBuff, byte appPrivileges,
            int channelInstanceSize,
            int channelAppletMemSize) throws TPSException, IOException {

        CMS.debug("SecureChannel.installApplet: entering...");

        // Would be tough to put a check on the various input sizes, let the applet
        // decide if the values are appropriate for channelInstanceSize and channelAppletMemSize

        if (netkeyPAIDBuff == null || netkeyAIDBuff == null || channelInstanceSize < 0 || channelAppletMemSize < 0) {
            throw new TPSException("SecureChannel.installApplet. Invalid input parameters!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

        }

        InstallAppletAPDU install = new InstallAppletAPDU(netkeyPAIDBuff, netkeyAIDBuff, appPrivileges,
                channelInstanceSize, channelAppletMemSize);

        computeAPDU(install);

        APDUResponse response = processor.handleAPDURequest(install);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.installApplett. Failed installApplet operation.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

    }

    // Burn the phone home URL into the token.
    public void setIssuerInfo(TPSBuffer issuerInfoBuff) throws TPSException, IOException {
        CMS.debug("SecureChannel.setIssuerInfo entering...");

        final int finalIssuerLength = 224;
        final int approxMinUrlSize = 5;

        if (issuerInfoBuff == null || issuerInfoBuff.size() < approxMinUrlSize) {
            throw new TPSException("SecureChannel.setIssuerInfo: Invalid input data.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        int issuerLen = issuerInfoBuff.size();

        int paddingLen = finalIssuerLength - issuerLen;

        TPSBuffer paddingBuff = new TPSBuffer(paddingLen, (byte) 0x0);

        TPSBuffer finalIssuerBuff = new TPSBuffer(issuerInfoBuff);

        finalIssuerBuff.add(paddingBuff);

        CMS.debug("finalIssuerBuff len: " + finalIssuerBuff.size() + " issuerInfo: " + finalIssuerBuff.toString());
        SetIssuerInfoAPDU setIssuer = new SetIssuerInfoAPDU((byte) 0x0, (byte) 0x0, finalIssuerBuff);

        computeAPDU(setIssuer);

        APDUResponse response = processor.handleAPDURequest(setIssuer);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.setIssuerInfo. Failed to set issuer info!",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        CMS.debug("SecureChannel.setIssuerInfo: leaving...");

    }

    public TPSBuffer getKeyDiversificationData() {
        return keyDiversificationData;
    }

    public TPSBuffer getCardChallenge() {
        return cardChallenge;
    }

    public TPSBuffer getHostChallenge() {
        return hostChallenge;
    }

    public TPSBuffer getHostCryptogram() {
        return hostCryptogram;
    }

    public TPSBuffer getCardCryptogram() {
        return cardCryptogram;
    }

}
