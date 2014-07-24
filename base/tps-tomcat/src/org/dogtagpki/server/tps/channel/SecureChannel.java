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
import org.dogtagpki.tps.apdu.CreateObjectAPDU;
import org.dogtagpki.tps.apdu.CreatePinAPDU;
import org.dogtagpki.tps.apdu.DeleteFileAPDU;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU.SecurityLevel;
import org.dogtagpki.tps.apdu.GenerateKeyAPDU;
import org.dogtagpki.tps.apdu.GenerateKeyECCAPDU;
import org.dogtagpki.tps.apdu.InstallAppletAPDU;
import org.dogtagpki.tps.apdu.InstallLoadAPDU;
import org.dogtagpki.tps.apdu.LifecycleAPDU;
import org.dogtagpki.tps.apdu.LoadFileAPDU;
import org.dogtagpki.tps.apdu.PutKeyAPDU;
import org.dogtagpki.tps.apdu.ReadObjectAPDU;
import org.dogtagpki.tps.apdu.SetIssuerInfoAPDU;
import org.dogtagpki.tps.apdu.SetPinAPDU;
import org.dogtagpki.tps.apdu.WriteObjectAPDU;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;
import org.mozilla.jss.pkcs11.PK11SymKey;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

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
    private TPSBuffer keyInfoData;
    private SecurityLevel secLevel;

    public enum TokenKeyType {
        KEY_TYPE_ENCRYPTION,
        KEY_TYPE_SIGNING,
        KEY_TYPE_SIGNING_AND_ENCRYPTION
    }

    public SecureChannel(TPSProcessor processor, PK11SymKey sessionKey, PK11SymKey encSessionKey, TPSBuffer drmDesKey,
            TPSBuffer kekDesKey, TPSBuffer keyCheck, TPSBuffer keyDiversificationData, TPSBuffer cardChallenge,
            TPSBuffer cardCryptogram, TPSBuffer hostChallenge, TPSBuffer hostCryptogram, TPSBuffer keyInfoData)
            throws TPSException {

        if (processor == null || sessionKey == null | encSessionKey == null || keyDiversificationData == null
                || cardChallenge == null || cardCryptogram == null || hostChallenge == null || hostCryptogram == null
                || keyInfoData == null) {
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
        this.keyInfoData = keyInfoData;

        this.secLevel = SecurityLevel.SECURE_MSG_MAC_ENC;
        //ToDo: Write method that reads this from the config

    }

    public static void main(String[] args) {
    }

    public void appendPKCS11Attribute(TPSBuffer buffer, long type, TPSBuffer attribute) {

        buffer.addLong4Bytes(type);

        buffer.addInt2Bytes(attribute.size());
        buffer.add(attribute);
    }

    public void appendKeyCapabilities(TPSBuffer buffer, String keyTypePrefix, String keyType) throws TPSException {

        if (buffer == null || keyTypePrefix == null || keyType == null) {
            throw new TPSException("SecureChannel.appdndKeyCabalities: Invalid input datat.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        IConfigStore configStore = CMS.getConfigStore();

        final String keyCapabilities = "keyCapabilities";

        try {

            boolean value = false;
            String configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "encrypt";

            value = configStore.getBoolean(configName);

            TPSBuffer attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_ENCRYPT, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "sign";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_SIGN, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "signRecover";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_SIGN_RECOVER, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "decrypt";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_DECRYPT, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "derive";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_DERIVE, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "unwrap";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_UNWRAP, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "wrap";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_WRAP, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "verifyRecover";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_VERIFY_RECOVER, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "verify";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_VERIFY, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "sensitive";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_SENSITIVE, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "private";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_PRIVATE, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "token";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_TOKEN, attr);

            CMS.debug("SecureChannel.appendKeyCapabilities: returning: " + buffer.toHexString());

        } catch (EBaseException e) {
            throw new TPSException("SecureChannel.appentKeyCapabilities. Can't obtain config value!",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }
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

    public TPSBuffer getKeyInfoData() {
        return keyInfoData;
    }

    public void writeObject(TPSBuffer objectID, TPSBuffer objectData) throws TPSException, IOException {
        CMS.debug("SecureChannel.writeObject: entering ...");

        if (objectID == null || objectData == null) {
            throw new TPSException("SecureChannel.writeObject: invalid input data.");
        }

        final int MAX_WRITE_SIZE = 0xd0;

        int offset = 0;
        int toSend = objectData.size();
        int blockSize = 0;

        boolean moreToGo = true;
        do {

            if (toSend > MAX_WRITE_SIZE) {
                blockSize = MAX_WRITE_SIZE;
            } else {
                blockSize = toSend;
            }

            TPSBuffer blockToSend = objectData.substr(offset, blockSize);

            WriteObjectAPDU write = new WriteObjectAPDU(objectID.toBytesArray(), offset, blockToSend);

            computeAPDU(write);

            APDUResponse response = processor.handleAPDURequest(write);

            if (!response.checkResult()) {
                CMS.debug("SecureChannel.writeObject: bad apdu return!");
                //Throw this return code because this happens during enrollment and we don't have
                // a more specific error code.
                throw new TPSException("SecureChannel.writeObject. Failed in middle of writeObject.",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

            offset += blockSize;
            toSend -= blockSize;

            if (toSend <= 0) {
                moreToGo = false;
            }

        } while (moreToGo);

    }

    public TPSBuffer readObject(TPSBuffer objectID, int offset, int len) throws TPSException, IOException {

        CMS.debug("SecureChannel.readObject: entering ...");

        if (objectID == null || len == 0) {
            throw new TPSException("SecureChannel.readObject: invalid input data.",
                    TPSStatus.STATUS_ERROR_READ_OBJECT_PDU);
        }

        final int MAX_READ_BUFFER_SIZE = 0xd0;

        ReadObjectAPDU read = null;
        TPSBuffer result = new TPSBuffer();

        int cur_read = 0;
        int cur_offset = 0;
        int sum = 0;

        if (len > MAX_READ_BUFFER_SIZE) {
            cur_offset = offset;
            cur_read = MAX_READ_BUFFER_SIZE;
        } else {
            cur_offset = offset;
            cur_read = len;
        }

        while (sum < len) {

            read = new ReadObjectAPDU(objectID.toBytesArray(), cur_offset, cur_read);
            computeAPDU(read);

            APDUResponse response = processor.handleAPDURequest(read);

            if (!response.checkResult()) {
                CMS.debug("SecureChannel.readObject: bad apdu return!");
                throw new TPSException("SecureChannel.installApplett. Failed in middle of readObject.",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            TPSBuffer resp = response.getResultDataNoCode();

            result.add(resp);

            sum += resp.size();
            cur_offset += resp.size();

            if ((len - sum) < MAX_READ_BUFFER_SIZE) {
                cur_read = len - sum;
            } else {
                cur_read = MAX_READ_BUFFER_SIZE;
            }

        }

        return result;
    }

    public void createObject(TPSBuffer objectID, TPSBuffer permissions, TPSBuffer object) throws TPSException,
            IOException {

        CMS.debug("SecureChannel.createObject: with full object. entering...");

        if (objectID == null || permissions == null || object == null) {
            throw new TPSException("SecureChannel.createObject, with full object. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        createObject(objectID, permissions, object.size());

        writeObject(objectID, object);

    }

    public void createCertificate(TPSBuffer objectID, TPSBuffer cert) throws TPSException, IOException {
        CMS.debug("SecureChannel.createCertificate: entering...");

        if (objectID == null || cert == null) {
            throw new TPSException("SecureChannel.createCertificate. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(objectID, permissions, cert);

    }

    public void createPKCS11CertAttrs(TokenKeyType keyType, String id, String label, TPSBuffer keyid)
            throws TPSException, IOException {

        TPSBuffer buffer = createPKCS11CertAttrsBuffer(keyType, id, label, keyid);

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(new TPSBuffer(id), permissions, buffer);

    }

    public TPSBuffer createPKCS11PriKeyAttrsBuffer(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, String keyTypePrefix) throws TPSException {

        TPSBuffer result = new TPSBuffer();

        CMS.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PriKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer:  id: " + id + " label: " + label + " keyid: "
                + keyid.toHexString());

        byte keytype[] = { 0, 0, 0, 0 };
        byte p11class[] = { 3, 0, 0, 0 };

        appendPKCS11Attribute(result, PKCS11Constants.CKA_MODULUS, modulus);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_KEY_TYPE, new TPSBuffer(keytype));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CLASS, new TPSBuffer(p11class));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_ID, keyid);
        appendKeyCapabilities(result, keyTypePrefix, "private");

        finalizeObjectBuffer(result, id);

        CMS.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: returing: " + result.toHexString());

        return result;

    }

    public void createPKCS11PriKeyAttrs(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, String keyTypePrefix) throws TPSException, IOException {

        CMS.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PriKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSBuffer buffer = createPKCS11PriKeyAttrsBuffer(id, label, keyid, modulus, keyTypePrefix);

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(new TPSBuffer(id), permissions, buffer);
    }

    public TPSBuffer createPKCS11PublicKeyAttrsBuffer(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, TPSBuffer exponent, String keyTypePrefix) throws TPSException {

        TPSBuffer result = new TPSBuffer();
        CMS.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || exponent == null
                || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PublicKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        byte p11class[] = { 2, 0, 0, 0 };

        appendPKCS11Attribute(result, PKCS11Constants.CKA_PUBLIC_EXPONENT, exponent);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_MODULUS, modulus);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_ID, keyid);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CLASS, new TPSBuffer(p11class));
        appendKeyCapabilities(result, keyTypePrefix, "public");

        finalizeObjectBuffer(result, id);

        CMS.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: returing: " + result.toHexString());

        return result;

    }

    public void createPKCS11PublicKeyAttrs(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, TPSBuffer exponent, String keyTypePrefix) throws TPSException, IOException {

        CMS.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || exponent == null
                || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PriKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSBuffer buffer = createPKCS11PriKeyAttrsBuffer(id, label, keyid, modulus, keyTypePrefix);

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(new TPSBuffer(id), permissions, buffer);

    }

    public void finalizeObjectBuffer(TPSBuffer buffer, String id) {

        TPSBuffer header = new TPSBuffer();

        header.add((byte) 0);
        header.add((byte) id.charAt(0));
        header.add((byte) id.charAt(1));
        header.add((byte) 0);
        header.add((byte) 0);

        header.add((byte) ((buffer.size()) / 256));
        header.add((byte) ((buffer.size()) % 256));

        buffer.prepend(header);

    }

    public TPSBuffer createPKCS11CertAttrsBuffer(TokenKeyType keyType, String id, String label, TPSBuffer keyid)
            throws TPSException {

        CMS.debug("SecureChannel.createPKCS11CertAttrsBuffer: entering... id: " + id);
        if (keyType == null || id == null || label == null || keyid == null) {
            throw new TPSException("SecureChannel.createPKCS11CertAttrsBuffer. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        CMS.debug("SecureChannel.createPKCS11CertAttrsBuffer: ... id: " + id + " label: " + label + " keyid: "
                + keyid.toHexString());

        byte[] type = { 0x0, 0x0, 0x0, 0x0 };
        byte[] p11class = { 0x1, 0x0, 0x0, 0x0 };
        byte[] tokenFlag = { 0x1 };

        TPSBuffer result = new TPSBuffer();

        CMS.debug("SecureChannel.createPKCS11CertAttrsBuffer: label: " + label + " label bytes: "
                + (new TPSBuffer(label)).toHexString());

        appendPKCS11Attribute(result, PKCS11Constants.CKA_LABEL, new TPSBuffer(label.getBytes()));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_ID, keyid);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CERTIFICATE_TYPE, new TPSBuffer(type));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CLASS, new TPSBuffer(p11class));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_TOKEN, new TPSBuffer(tokenFlag));

        finalizeObjectBuffer(result, id);

        CMS.debug("SecureChannel.createPKCS11CertAttrsBuffer: returing: " + result.toHexString());

        return result;

    }

    public void createObject(TPSBuffer objectID, TPSBuffer permissions, int len) throws TPSException, IOException {

        CMS.debug("SecureChannel.createObject: entering...");
        if (objectID == null || permissions == null || len <= 0) {
            throw new TPSException("SecureChannel.createObject. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CreateObjectAPDU create = new CreateObjectAPDU(objectID.toBytesArray(), permissions.toBytesArray(), len);

        computeAPDU(create);

        APDUResponse response = processor.handleAPDURequest(create);

        //Throw this return code because this happens during enrollment and we don't have
        // a more specific error code.
        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.createObject. Failed to create object on token.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

    }

    public int startEnrollment(int pe1, int pe2, TPSBuffer wrappedChallenge, TPSBuffer keyCheck, int algorithm,
            int keySize, int option) throws TPSException, IOException {

        if (wrappedChallenge == null) {
            throw new TPSException("SecureChannel.startEnrollment. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("SecureChannel.startEnrollment: entering ...");

        boolean isECC = processor.getTPSEngine().isAlgorithmECC(algorithm);

        GenerateKeyAPDU generate_key_apdu = null;
        GenerateKeyECCAPDU generate_ecc_key_apdu = null;

        APDUResponse response = null;
        if (isECC) {

            generate_ecc_key_apdu = new GenerateKeyECCAPDU((byte) pe1, (byte) pe2, (byte) algorithm, keySize,
                    (byte) option, (byte) 0, wrappedChallenge, keyCheck);

            computeAPDU(generate_ecc_key_apdu);

            response = processor.handleAPDURequest(generate_ecc_key_apdu);

            if (!response.checkResult()) {
                throw new TPSException("SecureChannel.startEnrollment. Failed generate key on token.",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        } else {

            generate_key_apdu = new GenerateKeyAPDU((byte) pe1, (byte) pe2, (byte) algorithm, keySize,
                    (byte) option, (byte) 0, wrappedChallenge, keyCheck);

            computeAPDU(generate_key_apdu);

            response = processor.handleAPDURequest(generate_key_apdu);

            if (!response.checkResult()) {
                throw new TPSException("SecureChannel.startEnrollment. Failed generate key on token.",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        }

        TPSBuffer data = response.getData();

        int size = data.getIntFrom2Bytes(0);

        CMS.debug("SecureChannel.startEnrollment: returning key size: " + size);

        return size;

    }

    public int tokenTypeToInt(TokenKeyType type) {

        if (type == TokenKeyType.KEY_TYPE_ENCRYPTION)
            return 0;

        if (type == TokenKeyType.KEY_TYPE_SIGNING)
            return 1;
        else
            return 2;
    }

    public void setLifeycleState(byte flag) throws TPSException, IOException {

        CMS.debug("SecureChannel.setLifecycleState: flage: " + flag);

        LifecycleAPDU life = new LifecycleAPDU(flag);

        computeAPDU(life);

        APDUResponse response = processor.handleAPDURequest(life);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.setLifecycleState. Failed to set Lifecycle State!.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

    }

    public void createPin(int pinNumber, int maxRetries, String pin) throws TPSException, IOException {

        CMS.debug("SecureChannel.createPin:  entering...");

        if (pin == null) {
            throw new TPSException("SecureChannel.createPin: invalid intput data.",
                    TPSStatus.STATUS_ERROR_TOKEN_RESET_PIN_FAILED);
        }

        TPSBuffer pinBuf = new TPSBuffer(pin.getBytes());
        CreatePinAPDU create = new CreatePinAPDU((byte) pinNumber, (byte) maxRetries, pinBuf);

        computeAPDU(create);

        @SuppressWarnings("unused")
        APDUResponse response = processor.handleAPDURequest(create);

        //If the pin already exists we may get an error here, but we go on.

    }

    public void resetPin(int pinNumber, String new_pin) throws TPSException, IOException {

        CMS.debug("SecureChannel.resetPin");

        if (new_pin == null) {
            throw new TPSException("SecureChannel.resetPin: invalid intput data.",
                    TPSStatus.STATUS_ERROR_TOKEN_RESET_PIN_FAILED);
        }

        TPSBuffer newPinBuf = new TPSBuffer(new_pin.getBytes());

        SetPinAPDU reset = new SetPinAPDU((byte) 0x0, (byte) 0x0, newPinBuf);

        computeAPDU(reset);

        APDUResponse response = processor.handleAPDURequest(reset);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.resetPin: failed to reset pin.",
                    TPSStatus.STATUS_ERROR_TOKEN_RESET_PIN_FAILED);
        }

    }

    public void putKeys(byte curVersion, byte curIndex, TPSBuffer keySetData) throws TPSException, IOException {

        CMS.debug("SecureChannel.putKeys: entering..");

        if (keySetData == null) {
            throw new TPSException("SecureChannel.putKeys: Invalid input data!", TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

        byte keyVersion = curVersion;

        if (curVersion == 0xff) {
            keyVersion = 0x0;
        }

        PutKeyAPDU putKey = new PutKeyAPDU(keyVersion, (byte) (0x80 | curIndex), keySetData);

        computeAPDU(putKey);

        APDUResponse response = processor.handleAPDURequest(putKey);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.putKeys: failed to upgrade key set!",
                    TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

    }

}
