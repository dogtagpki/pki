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
