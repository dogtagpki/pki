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
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.authentication.AuthUIParameter;
import org.dogtagpki.server.tps.authentication.TPSAuthenticator;
import org.dogtagpki.server.tps.channel.PlatformAndSecChannelProtoInfo;
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.server.tps.cms.CARemoteRequestHandler;
import org.dogtagpki.server.tps.cms.CARevokeCertResponse;
import org.dogtagpki.server.tps.cms.TKSComputeRandomDataResponse;
import org.dogtagpki.server.tps.cms.TKSComputeSessionKeyResponse;
import org.dogtagpki.server.tps.cms.TKSEncryptDataResponse;
import org.dogtagpki.server.tps.cms.TKSRemoteRequestHandler;
import org.dogtagpki.server.tps.config.ProfileDatabase;
import org.dogtagpki.server.tps.dbs.ActivityDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenCertStatus;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.main.ExternalRegAttrs;
//import org.dogtagpki.server.tps.main.ExternalRegCertToDelete;
import org.dogtagpki.server.tps.main.ExternalRegCertToRecover;
import org.dogtagpki.server.tps.mapping.BaseMappingResolver;
import org.dogtagpki.server.tps.mapping.FilterMappingParams;
import org.dogtagpki.tps.apdu.APDU;
import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.apdu.GetDataAPDU;
import org.dogtagpki.tps.apdu.GetLifecycleAPDU;
import org.dogtagpki.tps.apdu.GetStatusAPDU;
import org.dogtagpki.tps.apdu.GetVersionAPDU;
import org.dogtagpki.tps.apdu.InitializeUpdateAPDU;
import org.dogtagpki.tps.apdu.ListObjectsAPDU;
import org.dogtagpki.tps.apdu.SelectAPDU;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;
import org.dogtagpki.tps.msg.ExtendedLoginRequestMsg;
import org.dogtagpki.tps.msg.ExtendedLoginResponseMsg;
import org.dogtagpki.tps.msg.LoginRequestMsg;
import org.dogtagpki.tps.msg.LoginResponseMsg;
import org.dogtagpki.tps.msg.NewPinRequestMsg;
import org.dogtagpki.tps.msg.NewPinResponseMsg;
import org.dogtagpki.tps.msg.StatusUpdateRequestMsg;
import org.dogtagpki.tps.msg.TPSMessage;
import org.dogtagpki.tps.msg.TokenPDURequestMsg;
import org.dogtagpki.tps.msg.TokenPDUResponseMsg;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.cms.servlet.tks.SecureChannelProtocol;
import com.netscape.symkey.SessionKey;

import netscape.security.x509.RevocationReason;

public class TPSProcessor {

    public static final int RESULT_NO_ERROR = 0;
    public static final int RESULT_ERROR = -1;

    public static final int CPLC_DATA_SIZE = 47;
    public static final int CPLC_MSN_INDEX = 41;
    public static final int CPLC_MSN_SIZE = 4;

    public static final int INIT_UPDATE_DATA_SIZE = 28;
    public static final int DIVERSIFICATION_DATA_SIZE = 10;
    public static final int CARD_CRYPTOGRAM_OFFSET = 20;
    public static final int CARD_CRYPTOGRAM_SIZE = 8;
    public static final int CARD_CHALLENGE_SIZE_GP211_SC02 = 6;
    public static final int SEQUENCE_COUNTER_OFFSET_GP211_SC02 = 12;
    public static final int SEQUENCE_COUNTER_SIZE_GP211_SC02 = 2;
    public static final int CARD_CHALLENGE_OFFSET = 12;
    public static final int CARD_CHALLENGE_OFFSET_GP211_SC02 = 14;
    public static final int CARD_CHALLENGE_SIZE = 8;

    protected boolean isExternalReg;

    protected TPSSession session;
    //protected TokenRecord tokenRecord;
    protected String selectedTokenType;
    protected String selectedKeySet;
    IAuthToken authToken;
    List<String> ldapStringAttrs;

    protected String userid = null;
    protected String currentTokenOperation;

    protected BeginOpMsg beginMsg;
    private PlatformAndSecChannelProtoInfo platProtInfo;

    ProfileDatabase profileDatabase = new ProfileDatabase();

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();

    public TPSProcessor(TPSSession session) {
        setSession(session);
    }

    protected void setCurrentTokenOperation(String op) {
        currentTokenOperation = op;
    }

    protected void setSession(TPSSession session) {
        if (session == null) {
            throw new NullPointerException("TPS session is null");
        }
        this.session = session;
    }

    protected TPSSession getSession() {
        return session;
    }

    protected TokenRecord getTokenRecord() {
        TPSSession session = getSession();
        return session.getTokenRecord();
    }

    protected void setBeginMessage(BeginOpMsg msg) {
        beginMsg = msg;
    }

    public BeginOpMsg getBeginMessage() {
        return beginMsg;
    }

    protected void setSelectedTokenType(String theTokenType) {

        if (theTokenType == null) {
            throw new NullPointerException("TPSProcessor.setSelectedTokenType: Attempt to set invalid null token type!");
        }
        CMS.debug("TPS_Processor.setSelectedTokenType: tokenType=" +
                theTokenType);
        selectedTokenType = theTokenType;

        TokenRecord tokenRecord = getTokenRecord();

        if (tokenRecord == null) {
            throw new NullPointerException("TPSProcessor.setSelectedTokenType: Can't find token record for token!");
        }
        tokenRecord.setType(selectedTokenType);
    }

    public String getSelectedTokenType() {
        return selectedTokenType;
    }

    protected void setSelectedKeySet(String theKeySet) {

        if (theKeySet == null) {
            throw new NullPointerException("TPSProcessor.setSelectedKeySet: Attempt to set invalid null key set!");
        }
        CMS.debug("TPS_Processor.setSelectedKeySet: keySet=" +
                theKeySet);
        selectedKeySet = theKeySet;

    }

    public String getSelectedKeySet() {
        return selectedKeySet;
    }


    protected TPSBuffer extractTokenMSN(TPSBuffer cplc_data) throws TPSException {
        //Just make sure no one is inputing bogus cplc_data
        if (cplc_data == null || cplc_data.size() < CPLC_DATA_SIZE) {
            throw new TPSException("TPSProcessor.extractTokenMSN: Can't extract token msn from cplc data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        TPSBuffer token_msn = cplc_data.substr(CPLC_MSN_INDEX, CPLC_MSN_SIZE);
        return token_msn;

    }

    protected TPSBuffer extractTokenCUID(TPSBuffer cplc_data) throws TPSException {
        //Just make sure no one is inputing bogus cplc_data
        if (cplc_data == null || cplc_data.size() < CPLC_DATA_SIZE) {
            CMS.debug("TPS_Processor.extractTokenCUID: cplc_data: invalid length.");
            throw new TPSException("TPSProcessor.extractTokenCUID: Can't extract cuid from cplc data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        TPSBuffer token1 = cplc_data.substr(3, 4);
        TPSBuffer token2 = cplc_data.substr(19, 2);
        TPSBuffer token3 = cplc_data.substr(15, 4);

        TPSBuffer token_cuid = new TPSBuffer();

        token_cuid.add(token1);
        token_cuid.add(token2);
        token_cuid.add(token3);

        return token_cuid;

    }

    /**
     * Select applet.
     *
     * Global Platform Open Platform Card Specification
     * Version 2.0.1 Page 9-22
     *
     * Sample Data:
     *
     * _____________ CLA
     * | __________ INS
     * | | _______ P1
     * | | | ____ P2
     * | | | | _ Len
     * | | | | |
     * 00 A4 04 00 07
     * 53 4C 42 47 49 4E 41
     *
     * @throws IOException
     * @throws TPSException
     *
     */

    protected APDUResponse selectApplet(byte p1, byte p2, TPSBuffer aid) throws IOException, TPSException {

        CMS.debug("In TPS_Processor.SelectApplet.");

        if (aid == null || aid.size() == 0) {
            throw new TPSException("TPSProcessor.selectApplet: Invalid aid value!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        SelectAPDU select_apdu = new SelectAPDU(p1, p2, aid);

        //return the Response because the caller can
        //decide what to do, not every failure is fatal.
        //For instance the coolkey applet may not yet exist.
        return handleAPDURequest(select_apdu);

    }

    protected TPSBuffer getStatus() throws IOException, TPSException {

        CMS.debug("In TPS_Processor.GetStatus.");

        GetStatusAPDU get_status_apdu = new GetStatusAPDU();

        return handleAPDURequest(get_status_apdu).getData();
    }

    public APDUResponse handleAPDURequest(APDU apdu) throws IOException, TPSException {

        if (apdu == null) {
            throw new TPSException("TPSProcessor.handleAPDURequest: invalid incoming apdu!");
        }

        TokenPDURequestMsg request_msg = new TokenPDURequestMsg(apdu);

        try {
            session.write(request_msg);
        } catch (IOException e) {
            CMS.debug("TPS_Processor.HandleAPDURequest failed WriteMsg: " + e.toString());
            throw e;

        }

        TokenPDUResponseMsg response_msg = null;

        try {
            response_msg = (TokenPDUResponseMsg) session.read();
        } catch (IOException e) {
            CMS.debug("TPS_Processor.HandleAPDURequest failed ReadMsg: " + e.toString());
            throw e;

        }

        return response_msg.getResponseAPDU();
    }

    protected TPSBuffer getCplcData() throws IOException, TPSException {
        CMS.debug("In TPS_Processor. getCplcData");

        GetDataAPDU get_data_apdu = new GetDataAPDU();

        APDUResponse respApdu = handleAPDURequest(get_data_apdu);

        if (!respApdu.checkResult()) {
            throw new TPSException("TPSProcessor.getCplcData: Can't get data!", TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }
        TPSBuffer cplcData = respApdu.getData();

        if (cplcData.size() != CPLC_DATA_SIZE) {
            throw new TPSException("TPSProcessor.cplcData: Data invalid size!", TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        return respApdu.getData();
    }

    public TPSBuffer getData(byte[] identifier) throws TPSException, IOException {
        CMS.debug("In TPSProcessor.getData: identifier: " + identifier.toString());

        if (identifier == null || identifier.length != 2) {
            throw new TPSException("TPSProcessor.getData: Can't get data, invalid input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }
        GetDataAPDU get_data_apdu = new GetDataAPDU(identifier);

        APDUResponse respApdu = handleAPDURequest(get_data_apdu);

        if (!respApdu.checkResult()) {
            throw new TPSException("TPSProcessor.getData: Can't get data!", TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        return respApdu.getData();
    }

    protected TPSBuffer getAppletVersion() throws IOException, TPSException {
        //We return null if no applet present
        // This is not an error, the token can be blank.

        CMS.debug("In TPSProcessor.getAppletVersion");

        selectCoolKeyApplet();

        GetVersionAPDU get_version_apdu = new GetVersionAPDU();

        APDUResponse respApdu = handleAPDURequest(get_version_apdu);

        if (!respApdu.checkResult()) {
            CMS.debug("TPSProcessor.getAppletVersion: No applet version found on card!");
            return null;
        }

        TPSBuffer apdu_data = respApdu.getData();

        if (apdu_data.size() != 6) {
            CMS.debug("TPSProcessor.getAppletVersion: incorrect return data size!");
            throw new TPSException("TPSProcessor.getAppletVersion: invalid applet version string returned!");
        }

        TPSBuffer build_id = apdu_data.substr(0, 4);

        CMS.debug("TPSProcessor.getAppletVersion: returning: " + build_id.toHexString());

        return build_id;

    }

    protected byte getLifecycleState() {

        byte resultState = (byte) 0xf0;

        String method = "TPSProcessor.getLifecycleState:";
        CMS.debug(".getLifecycleState: ");

        GetLifecycleAPDU getLifecycle = new GetLifecycleAPDU();

        try {

            selectCoolKeyApplet();

            APDUResponse response = handleAPDURequest(getLifecycle);

            if (!response.checkResult()) {
                return resultState;
            }

            TPSBuffer result = response.getResultDataNoCode();

            CMS.debug(method + " result size: " + result.size());

            //Only one byte of data returned not including the 2 result bytes

            if (result.size() == 1) {
                resultState = result.at(0);

                CMS.debug(method + " result: " + resultState);
            }

        } catch (TPSException | IOException e) {
             CMS.debug(method + " problem getting state: " + e);
        }

        return resultState;

    }


    protected TPSBuffer encryptData(AppletInfo appletInfo, TPSBuffer keyInfo, TPSBuffer plaintextChallenge,
            String connId) throws TPSException {

        TKSRemoteRequestHandler tks = null;

        TKSEncryptDataResponse data = null;

        try {
            tks = new TKSRemoteRequestHandler(connId, getSelectedKeySet());
            data = tks.encryptData(appletInfo.getKDD(),appletInfo.getCUID(), keyInfo, plaintextChallenge);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.encryptData: Erorr getting wrapped data from TKS!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        int status = data.getStatus();

        if (status != 0) {
            throw new TPSException("TPSProcessor.computeRandomData: Erorr getting wrapped data from TKS!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        return data.getEncryptedData();
    }

    TPSBuffer computeRandomData(int dataSize, String connId) throws TPSException {

        TKSRemoteRequestHandler tks = null;

        TKSComputeRandomDataResponse data = null;

        try {
            tks = new TKSRemoteRequestHandler(connId);
            data = tks.computeRandomData(dataSize);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.computeRandomData: Erorr getting random data from TKS!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        int status = data.getStatus();

        if (status != 0) {
            throw new TPSException("TPSProcessor.computeRandomData: Erorr getting random data from TKS!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        return data.getRandomData();
    }

    protected TPSBuffer initializeUpdate(byte keyVersion, byte keyIndex, TPSBuffer randomData) throws IOException,
            TPSException {

        CMS.debug("In TPS_Processor.initializeUpdate.");
        InitializeUpdateAPDU initUpdate = new InitializeUpdateAPDU(keyVersion, keyIndex, randomData);

        int done = 0;
        if (done == 1)
            throw new TPSException("TPSProcessor.initializeUpdate. debugging exit...");

        APDUResponse resp = handleAPDURequest(initUpdate);

        if (!resp.checkResult()) {
            CMS.debug("TPSProcessor.initializeUpdate: Failed intializeUpdate!");
            throw new TPSException("TPSBuffer.initializeUpdate: Failed initializeUpdate!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

        }

        TPSBuffer data = resp.getResultDataNoCode();

        if (data.size() != INIT_UPDATE_DATA_SIZE) {
            throw new TPSException("TPSBuffer.initializeUpdate: Invalid response from token!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        return data;

    }

    protected SecureChannel setupSecureChannel(AppletInfo appletInfo) throws TPSException, IOException {
        SecureChannel channel = null;

        //Create a standard secure channel with current key set.
        CMS.debug("TPSProcessor.setupSecureChannel: No arguments entering...");

        int defKeyVersion = getChannelDefKeyVersion();
        int defKeyIndex = getChannelDefKeyIndex();

        channel = setupSecureChannel((byte) defKeyVersion, (byte) defKeyIndex,
                getTKSConnectorID(),appletInfo);

        channel.externalAuthenticate();

        return channel;
    }

    protected SecureChannel setupSecureChannel(byte keyVersion, byte keyIndex,
            String connId,AppletInfo appletInfo)
            throws IOException, TPSException {

        //Assume generating host challenge on TKS, we no longer support not involving the TKS.

        CMS.debug("TPSProcessor.setupSecureChannel: keyVersion: " + keyVersion + " keyIndex: " + keyIndex
                );

        if(appletInfo == null) {
            throw new TPSException("TPSProcessor.setupSecureChannel: invalid input data.", TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
         }


        TPSBuffer randomData = computeRandomData(8, connId);
        if (randomData != null) {
            //CMS.debug("TPSProcessor.setupSecureChannel: obtained randomData: " + randomData.toHexString());
            CMS.debug("TPSProcessor.setupSecureChannel: obtained randomData");
        }

        acquireChannelPlatformAndProtocolInfo();

        TPSBuffer initUpdateResp = initializeUpdate(keyVersion, keyIndex, randomData);

        TPSBuffer key_diversification_data = initUpdateResp.substr(0, DIVERSIFICATION_DATA_SIZE);
        appletInfo.setKDD(key_diversification_data);

        CMS.debug("TPSProcessor.setupSecureChannel: diversification data: " + key_diversification_data.toHexString());

        TPSBuffer key_info_data = initUpdateResp.substr(DIVERSIFICATION_DATA_SIZE, 2);
        CMS.debug("TPSProcessor.setupSecureChannel: key info data: " + key_info_data.toHexString());

        TokenRecord tokenRecord = getTokenRecord();
        tokenRecord.setKeyInfo(key_info_data.toHexStringPlain());

        TPSBuffer card_cryptogram = null;
        TPSBuffer sequenceCounter = null;

        boolean isGp211scp02 = false;

        if (platProtInfo.getPlatform().equals(SecureChannel.GP211)) {
            isGp211scp02 = true;
        }

        card_cryptogram = initUpdateResp.substr(CARD_CRYPTOGRAM_OFFSET, CARD_CRYPTOGRAM_SIZE);
        //CMS.debug("TPSProcessor.setupSecureChannel: card cryptogram: " + card_cryptogram.toHexString());
        CMS.debug("TPSProcessor.setupSecureChannel: card cryptogram: extracted");

        TPSBuffer card_challenge = null;

        if (isGp211scp02) {
            sequenceCounter = initUpdateResp.substr(SEQUENCE_COUNTER_OFFSET_GP211_SC02, 2);

            {
                card_challenge = initUpdateResp
                        .substr(CARD_CHALLENGE_OFFSET_GP211_SC02, CARD_CHALLENGE_SIZE_GP211_SC02);
                card_cryptogram = initUpdateResp.substr(CARD_CRYPTOGRAM_OFFSET, CARD_CRYPTOGRAM_SIZE); //new TPSBuffer(canned_card_challenge);

                /*
                CMS.debug("TPSProcessor.setupSecureChannel 02: card cryptogram: " + card_cryptogram.toHexString());
                CMS.debug("TPSProcessor.setupSecureChannel 02: card challenge: " + card_challenge.toHexString());
                CMS.debug("TPSProcessor.setupSecureChannel 02: host challenge: " + randomData.toHexString());
                */
                CMS.debug("TPSProcessor.setupSecureChannel 02: card cryptogram: extracted");
                CMS.debug("TPSProcessor.setupSecureChannel 02: card challenge: extracted");

            }

            //Set the second byte of the keyInfo data to 0x1, this only gives us the secure protocol version 0x2 here.
            //This will allow symkey to not get confused with that 0x02.
            CMS.debug("TPSProcessor.setupSecureChannel 02: key Info , before massage: " + key_info_data.toHexString());
            key_info_data.setAt(1, (byte) 0x1);
            CMS.debug("TPSProcessor.setupSecureChannel 02: key Info , after massage: " + key_info_data.toHexString());

            tokenRecord.setKeyInfo(key_info_data.toHexStringPlain());

        } else {
            card_challenge = initUpdateResp.substr(CARD_CHALLENGE_OFFSET, CARD_CHALLENGE_SIZE);
        }
        //CMS.debug("TPSProcessor.setupSecureChannel: card challenge: " + card_challenge.toHexString());
        CMS.debug("TPSProcessor.setupSecureChannel: card challenge: extracted");

        SecureChannel channel = null;

        try {
            channel = generateSecureChannel(connId, key_diversification_data, key_info_data, card_challenge,
                    card_cryptogram,
                    randomData, sequenceCounter,appletInfo);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.setupSecureChannel: Can't set up secure channel: " + e,
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        return channel;

    }

    protected SecureChannel generateSecureChannel(String connId, TPSBuffer keyDiversificationData,
            TPSBuffer keyInfoData, TPSBuffer cardChallenge, TPSBuffer cardCryptogram, TPSBuffer hostChallenge,
            TPSBuffer sequenceCounter,AppletInfo appletInfo)
            throws EBaseException, TPSException, IOException {

        if (connId == null || keyDiversificationData == null || keyInfoData == null || cardChallenge == null
                || cardCryptogram == null || hostChallenge == null || appletInfo == null) {
            throw new TPSException("TPSProcessor.generateSecureChannel: Invalid input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        CMS.debug("TPSProcessor.generateSecureChannel: entering.. keyInfoData: " + keyInfoData.toHexString());
        CMS.debug("TPSProcessor.generateSecureChannel: isSCP02: " + platProtInfo.isSCP02());

        TPSEngine engine = getTPSEngine();

        SecureChannel channel = null;
        TPSBuffer hostCryptogram = null;
        PK11SymKey sessionKey = null;
        PK11SymKey encSessionKey = null;
        TKSComputeSessionKeyResponse resp = null;
        TKSComputeSessionKeyResponse respEnc02 = null;
        TKSComputeSessionKeyResponse respDek02 = null;
        TKSComputeSessionKeyResponse respCMac02 = null;
        TKSComputeSessionKeyResponse respRMac02 = null;

        PK11SymKey encSessionKeySCP02 = null;
        PK11SymKey dekSessionKeySCP02 = null;
        PK11SymKey cmacSessionKeySCP02 = null;
        PK11SymKey rmacSessionKeySCP02 = null;

        SymmetricKey sharedSecret = null;

        //Sanity checking

        boolean cuidOK = checkCUIDMatchesKDD(appletInfo.getCUIDhexStringPlain(), appletInfo.getKDDhexStringPlain());

        boolean isVersionInRange = checkCardGPKeyVersionIsInRange(appletInfo.getCUIDhexStringPlain(), appletInfo.getKDDhexStringPlain(), keyInfoData.toHexStringPlain());

        boolean doesVersionMatchTokenDB = checkCardGPKeyVersionMatchesTokenDB(appletInfo.getCUIDhexStringPlain(), appletInfo.getKDDhexStringPlain(), keyInfoData.toHexStringPlain());

        if(cuidOK == false) {
            throw new TPSException("TPSProcessor.generateSecureChannel: cuid vs kdd matching policy not met!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        if(isVersionInRange == false) {

            throw new TPSException("TPSProcessor.generateSecureChannel: key version is not within acceptable range!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        if(doesVersionMatchTokenDB == false) {
            throw new TPSException("TPSProcessor.generateSecureChannel: key version from token does not match that of the token db!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        SecureChannelProtocol protocol = new SecureChannelProtocol();

        String tokenName = "Internal Key Storage Token";

        CryptoManager cm = null;
        CryptoToken token = null;

        String sharedSecretName = null;
        try {
            sharedSecretName = getSharedSecretTransportKeyName(connId);
            SecureChannelProtocol.setSharedSecretKeyName(sharedSecretName);

            cm = protocol.getCryptoManger();
            token = protocol.returnTokenByName(tokenName, cm);

            sharedSecret = SecureChannelProtocol.getSymKeyByName(token, sharedSecretName);

            // sharedSecret = getSharedSecretTransportKey(connId);
        } catch (Exception e) {
            CMS.debug(e);
            throw new TPSException("TPSProcessor.generateSecureChannel: Can't get shared secret key!: " + e,
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        if (platProtInfo.isGP201() || platProtInfo.isSCP01()) {

            resp = engine.computeSessionKey(keyDiversificationData, appletInfo.getCUID(), keyInfoData,
                    cardChallenge, hostChallenge, cardCryptogram,
                    connId, getSelectedTokenType(), getSelectedKeySet());

            hostCryptogram = resp.getHostCryptogram();

            if (hostCryptogram == null) {
                throw new TPSException("TPSProcessor.generateSecureChannel: No host cryptogram returned from token!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

            }

            try {
                TPSBuffer sessionKeyWrapped = resp.getSessionKey();
                TPSBuffer encSessionKeyWrapped = resp.getEncSessionKey();

             /* sessionKey = SessionKey.UnwrapSessionKeyWithSharedSecret(tokenName, (PK11SymKey) sharedSecret,
                        sessionKeyWrapped.toBytesArray()); */


               sessionKey =  (PK11SymKey) protocol.unwrapWrappedSymKeyOnToken(token, sharedSecret, sessionKeyWrapped.toBytesArray(), false);


                if (sessionKey == null) {
                    CMS.debug("TPSProcessor.generateSecureChannel: Can't extract session key!");
                    throw new TPSException("TPSProcessor.generateSecureChannel: Can't extract session key!",
                            TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
                }

                CMS.debug("TPSProcessor.generateSecureChannel: retrieved session key: " + sessionKey);

              /*  encSessionKey = SessionKey.UnwrapSessionKeyWithSharedSecret(tokenName,(PK11SymKey) sharedSecret,
                        encSessionKeyWrapped.toBytesArray()); */

                encSessionKey = (PK11SymKey) protocol.unwrapWrappedSymKeyOnToken(token, sharedSecret,encSessionKeyWrapped.toBytesArray(),false);

                if (encSessionKey == null) {
                    CMS.debug("TPSProcessor.generateSecureChannel: Can't extract enc session key!");
                    throw new TPSException("TPSProcessor.generateSecureChannel: Can't extract enc session key!",
                            TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
                }

                CMS.debug("TPSProcessor.generateSecureChannel: retrieved enc session key");

                TPSBuffer drmDesKey = null;
                TPSBuffer kekDesKey = null;
                TPSBuffer keyCheck = null;

                drmDesKey = resp.getDRM_Trans_DesKey();
                keyCheck = resp.getKeyCheck();
                kekDesKey = resp.getKekWrappedDesKey();

                if (checkServerSideKeyGen(connId)) {
                    CMS.debug("TPSProcessor.generateSecureChannel: true for checkServerSideKeyGen");
                    /*
                    CMS.debug("TPSProcessor.generateSecureChannel: drmDesKey: " + drmDesKey + " kekDesKey : "
                            + kekDesKey
                            + " keyCheck: " + keyCheck);
                    */
                    //ToDo handle server side keygen.

                }
                channel = new SecureChannel(this, sessionKey, encSessionKey, drmDesKey,
                        kekDesKey, keyCheck, keyDiversificationData, cardChallenge,
                        cardCryptogram, hostChallenge, hostCryptogram, keyInfoData, platProtInfo);

            } catch (Exception e) {
                CMS.debug(e);
                e.printStackTrace();
                throw new TPSException("TPSProcessor.generateSecureChannel: Problem extracting session keys! " + e,
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

        }

        if (platProtInfo.isGP211() && platProtInfo.isSCP02()) {
            //Generate the 4 keys we need for SCP02, Impl 15

            if (sequenceCounter == null) {
                throw new TPSException("TPSProcessor.generateSecureChannel: Invalid input data!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            CMS.debug("TPSProcessor.generateSecureChannel Trying secure channel protocol 02");
            respEnc02 = engine.computeSessionKeySCP02(keyDiversificationData, appletInfo.getCUID(), keyInfoData,
                    sequenceCounter, new TPSBuffer(SecureChannel.ENCDerivationConstant),
                    connId, getSelectedTokenType(), getSelectedKeySet());

            TPSBuffer encSessionKeyWrappedSCP02 = respEnc02.getSessionKey();
            encSessionKeySCP02 = SessionKey.UnwrapSessionKeyWithSharedSecret(tokenName, (PK11SymKey) sharedSecret,
                    encSessionKeyWrappedSCP02.toBytesArray());

            if (encSessionKeySCP02 == null) {
                CMS.debug("TPSProcessor.generateSecureChannel: Can't extract the SCP02 enc session key!");
                throw new TPSException("TPSProcessor.generateSecureChannel: Can't the emc SCP02 session keys!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            respCMac02 = engine.computeSessionKeySCP02(keyDiversificationData, appletInfo.getCUID(), keyInfoData,
                    sequenceCounter, new TPSBuffer(SecureChannel.C_MACDerivationConstant),
                    connId, getSelectedTokenType(), getSelectedKeySet());

            TPSBuffer cmacSessionKeyWrappedSCP02 = respCMac02.getSessionKey();

            cmacSessionKeySCP02 = SessionKey.UnwrapSessionKeyWithSharedSecret(tokenName,(PK11SymKey) sharedSecret,
                    cmacSessionKeyWrappedSCP02.toBytesArray());

            if (cmacSessionKeySCP02 == null) {
                CMS.debug("TPSProcessor.generateSecureChannel: Can't extract the SCP02 cmac session key!");
                throw new TPSException("TPSProcessor.generateSecureChannel: Can't the s,ac SCP02 session keys!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            respRMac02 = engine.computeSessionKeySCP02(keyDiversificationData, appletInfo.getCUID(), keyInfoData,
                    sequenceCounter, new TPSBuffer(SecureChannel.R_MACDerivationConstant),
                    connId, getSelectedTokenType(), getSelectedKeySet());

            TPSBuffer rmacSessionKeyWrappedSCP02 = respRMac02.getSessionKey();

            rmacSessionKeySCP02 = SessionKey.UnwrapSessionKeyWithSharedSecret(tokenName,(PK11SymKey) sharedSecret,
                    rmacSessionKeyWrappedSCP02.toBytesArray());

            if (rmacSessionKeySCP02 == null) {
                CMS.debug("TPSProcessor.generateSecureChannel: Can't extract the SCP02 cmac session key!");
                throw new TPSException("TPSProcessor.generateSecureChannel: Can't the cmac SCP02 session keys!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            respDek02 = engine.computeSessionKeySCP02(keyDiversificationData, appletInfo.getCUID(), keyInfoData,
                    sequenceCounter, new TPSBuffer(SecureChannel.DEKDerivationConstant),
                    connId, getSelectedTokenType(), getSelectedKeySet());

            CMS.debug("Past engine.computeSessionKeyData: After dek key request.");

            TPSBuffer dekSessionKeyWrappedSCP02 = respDek02.getSessionKey();

            dekSessionKeySCP02 = SessionKey.UnwrapSessionKeyWithSharedSecret(tokenName,(PK11SymKey) sharedSecret,
                    dekSessionKeyWrappedSCP02.toBytesArray());

            if (dekSessionKeySCP02 == null) {
                CMS.debug("TPSProcessor.generateSecureChannel: Can't extract the SCP02 dek session key!");
                throw new TPSException("TPSProcessor.generateSecureChannel: Can't the dek SCP02 session keys!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            TPSBuffer drmDesKey = null;
            TPSBuffer kekDesKey = null;
            TPSBuffer keyCheck = null;

            drmDesKey = respDek02.getDRM_Trans_DesKey();
            kekDesKey = respDek02.getKekWrappedDesKey();
            keyCheck = respDek02.getKeyCheck();

            if (drmDesKey == null || kekDesKey == null) {
                CMS.debug("TPSProcessor.generateSecureChannel: Can't get drmDesKey or kekDesKey from TKS when processing the DEK session key!");
                throw new TPSException(
                        "TPSProcessor.generateSecureChannel: Can't get drmDesKey or kekDesKey from TKS when processing the DEK session key!",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            channel = new SecureChannel(this, encSessionKeySCP02, cmacSessionKeySCP02,
                    rmacSessionKeySCP02, dekSessionKeySCP02, drmDesKey, kekDesKey, keyCheck,
                    keyDiversificationData,
                    keyInfoData, sequenceCounter, hostChallenge, cardChallenge, cardCryptogram, platProtInfo);

            channel.setDekSessionKeyWrapped(dekSessionKeyWrappedSCP02);

        }

        if (channel == null) {
            throw new TPSException(
                    "TPSProcessor.generateSecureChannel: Can't create Secure Channel, possibly invalid secure channel protocol requested.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        return channel;
    }

    protected boolean checkUpdateAppletEncryption() throws TPSException {

        CMS.debug("TPSProcessor.checkUpdateAppletEncryption entering...");

        IConfigStore configStore = CMS.getConfigStore();

        String appletEncryptionConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_UPDATE_APPLET_ENCRYPTION;

        CMS.debug("TPSProcessor.checkUpdateAppletEncryption config to check: " + appletEncryptionConfig);

        boolean appletEncryption = false;

        try {
            appletEncryption = configStore.getBoolean(appletEncryptionConfig, false);
        } catch (EBaseException e) {
            //Default TPSException will return a "contact admin" error code.
            throw new TPSException(
                    "TPSProcessor.checkUpdateAppletEncryption: internal error in getting value from config.");
        }

        CMS.debug("TPSProcessor.checkUpdateAppletEncryption returning: " + appletEncryption);
        return appletEncryption;

    }

    protected int checkAndUpgradeApplet(AppletInfo appletInfo) throws TPSException, IOException {

        CMS.debug("checkAndUpgradeApplet: entering..");

        String tksConnId = getTKSConnectorID();

        int upgraded = 0;
        if (checkForAppletUpdateEnabled()) {

            String targetAppletVersion = checkForAppletUpgrade("op." + currentTokenOperation);
            targetAppletVersion = targetAppletVersion.toLowerCase();

            String currentAppletVersion = formatCurrentAppletVersion(appletInfo);

            CMS.debug("TPSProcessor.checkAndUpgradeApplet: currentAppletVersion: " + currentAppletVersion
                    + " targetAppletVersion: " + targetAppletVersion);

            if (targetAppletVersion.compareTo(currentAppletVersion) != 0) {

                upgraded = 1;
                CMS.debug("TPSProcessor.checkAndUpgradeApplet: Upgrading applet to : " + targetAppletVersion);
                upgradeApplet(appletInfo, "op." + currentTokenOperation, targetAppletVersion, getBeginMessage()
                        .getExtensions(),
                        tksConnId, 5, 12);
            }
        }

        if (upgraded == 0) {
            CMS.debug("TPSProcessor.checkAndUpgradeApplet: applet already at correct version or upgrade disabled.");

            // We didn't need to upgrade the applet but create new channel for now.
            selectCardManager();
            setupSecureChannel(appletInfo);

        }

        return upgraded;
    }

    protected void upgradeApplet(AppletInfo appletInfo, String operation, String new_version,
            Map<String, String> extensions, String connId, int startProgress, int endProgress) throws IOException,
            TPSException {

        TPSBuffer netkeyAIDBuff = null;
        TPSBuffer cardMgrAIDBuff = null;
        TPSBuffer netkeyPAIDBuff = null;

        netkeyAIDBuff = getNetkeyAID();
        netkeyPAIDBuff = getNetkeyPAID();
        cardMgrAIDBuff = getCardManagerAID();

        int channelBlockSize = getChannelBlockSize();
        int channelInstanceSize = getChannelInstanceSize();
        int channelAppletMemSize = getAppletMemorySize();
        int defKeyVersion = getChannelDefKeyVersion();
        int defKeyIndex = getChannelDefKeyIndex();

        byte[] appletData = null;

        TokenRecord tokenRecord = getTokenRecord();

        String directory = getAppletDirectory(operation);

        CMS.debug("TPSProcessor.upgradeApplet: applet target directory: " + directory);

        String appletFileExt = getAppletExtension();

        String appletFilePath = directory + "/" + new_version + "." + appletFileExt;

        CMS.debug("TPSProcessor.upgradeApplet: targe applet file name: " + appletFilePath);

        appletData = getAppletFileData(appletFilePath);

        APDUResponse select = selectApplet((byte) 0x04, (byte) 0x00, cardMgrAIDBuff);

        if (!select.checkResult()) {
            String logMsg = "Can't selelect the card manager!";
            auditAppletUpgrade(appletInfo, "failure", null /*unavailable*/, new_version, logMsg);
            throw new TPSException("TPSProcessor.upgradeApplet:" + logMsg);
        }

        SecureChannel channel = setupSecureChannel((byte) defKeyVersion, (byte) defKeyIndex, connId, appletInfo);

        channel.externalAuthenticate();

        channel.deleteFileX(netkeyAIDBuff);
        channel.deleteFileX(netkeyPAIDBuff);

        // Next step will be to load the applet file to token.

        channel.installLoad(netkeyPAIDBuff, cardMgrAIDBuff, appletData.length);

        TPSBuffer appletDataBuff = new TPSBuffer(appletData);

        channel.loadFile(appletDataBuff, channelBlockSize, startProgress, endProgress);

        channel.installApplet(netkeyPAIDBuff, netkeyAIDBuff, (byte) 0, channelInstanceSize, channelAppletMemSize);

        //Now select our new applet

        select = selectApplet((byte) 0x04, (byte) 0x00, netkeyAIDBuff);

        if (!select.checkResult()) {
            String logMsg = "Cannot select newly created applet!";
            auditAppletUpgrade(appletInfo, "failure", channel.getKeyInfoData().toHexStringPlain(), new_version, logMsg);
            throw new TPSException("TPSProcessor.upgradeApplet: " + logMsg,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        auditAppletUpgrade(appletInfo, "success", channel.getKeyInfoData().toHexStringPlain(), new_version, null);
        tokenRecord.setAppletID(new_version);

    }

    public void selectCoolKeyApplet() throws TPSException, IOException {

        CMS.debug("In selectCoolKeyApplet!");
        TPSBuffer netkeyAIDBuff = getNetkeyAID();

        APDUResponse select = selectApplet((byte) 0x04, (byte) 0x00, netkeyAIDBuff);

        if (!select.checkResult()) {
            CMS.debug("TPSProcessor.selectCoolKeyApplet: Can't select coolkey, token may be blank.");
            /* throw new TPSException("TPSProcessor.upgradeApplet: Cannot select newly created applet!",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
                    */
        }
    }

    protected byte[] getAppletFileData(String appletFilePath) throws IOException, TPSException {

        if (appletFilePath == null) {
            throw new TPSException("TPSProcessor.getAppletFileData: Invalid applet file name.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        byte[] contents = null;
        try {
            Path path = Paths.get(appletFilePath);
            contents = Files.readAllBytes(path);

        } catch (IOException e) {
            CMS.debug("TPSProcessor.getAppletFileData: IOException " + e);
            throw e;
        } catch (Exception e) {
            CMS.debug("PSProcessor.getAppletFileData: Exception: " + e);
            throw new TPSException("TPSProcessor.getAppletFileData: Exception: " + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        CMS.debug("TPSProcessor.getAppletFileData: data: " + contents);

        return contents;
    }

    /**
     * getAuthentication gets Authentication per configuration
     *
     * @param prefix config prefix for tokenType
     * @param tokenType the tokenType(profile)
     * @return Authentication
     */
    public TPSAuthenticator getAuthentication(String prefix, String tokenType)
            throws EBaseException {
        CMS.debug("TPSProcessor.getAuthentication");
        String logMsg = null;

        if (prefix.isEmpty() || tokenType.isEmpty()) {
            logMsg = "TPSProcessor.getAuthentication: missing parameters: prefix or tokenType";
            CMS.debug(logMsg);
            throw new EBaseException(logMsg);
        }
        IConfigStore configStore = CMS.getConfigStore();
        String configName = prefix + "." + tokenType + ".auth.id";
        String authId;

        CMS.debug("TPSProcessor.getAuthentication: getting config: " +
                configName);
        authId = configStore.getString(configName);
        if (authId == null) {
            logMsg = "TPSProcessor.getAuthentication: config param not found:" + configName;
            CMS.debug(logMsg);
            throw new EBaseException(logMsg);
        }
        return getAuthentication(authId);
    }

    public TPSAuthenticator getAuthentication(String authId)
            throws EBaseException {
        CMS.debug("TPSProcessor.getAuthentication");
        String logMsg = null;

        if (authId.isEmpty()) {
            logMsg = "TPSProcessor.getAuthentication: missing parameters: authId";
            CMS.debug(logMsg);
            throw new EBaseException(logMsg);
        }
        IConfigStore configStore = CMS.getConfigStore();

        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        TPSAuthenticator authInst =
                subsystem.getAuthenticationManager().getAuthInstance(authId);
        String authCredNameConf = "auths.instance." + authId + ".authCredName";
        CMS.debug("TPSProcessor.getAuthentication: getting config: " +
                authCredNameConf);
        String authCredName = configStore.getString(authCredNameConf);
        if (authCredName == null) {
            logMsg = "TPSProcessor.getAuthentication: config param not found:" + authCredNameConf;
            CMS.debug(logMsg);
            throw new EBaseException(logMsg);
        }
        authInst.setAuthCredName(authCredName);

        // set ldapStringAttrs for later processing
        String authLdapStringAttrs = "auths.instance." + authId + ".ldapStringAttributes";
        CMS.debug("TPSProcessor.getAuthentication: getting config: " +
                authLdapStringAttrs);
        String authLdapStringAttributes = configStore.getString(authLdapStringAttrs, "");
        if (authLdapStringAttributes != null && !authLdapStringAttributes.equals("")) {
            logMsg = "TPSProcessor.getAuthentication: got ldapStringAttributes... setting up";
            CMS.debug(logMsg);
            ldapStringAttrs = Arrays.asList(authLdapStringAttributes.split(","));
        } else {
            // not set is okay
            logMsg = "TPSProcessor.getAuthentication: config param not set:" + authLdapStringAttributes;
            CMS.debug(logMsg);
        }

        return authInst;
    }

    public void processAuthentication(String op, TPSAuthenticator userAuth, String cuid, TokenRecord tokenRecord)
            throws EBaseException, TPSException, IOException {
        IAuthCredentials userCred;
        String method = "TPSProcessor:processAuthentication:";
        String opPrefix;
        if (op.equals(TPSEngine.FORMAT_OP))
            opPrefix = TPSEngine.OP_FORMAT_PREFIX;
        else if (op.equals(TPSEngine.ENROLL_OP))
            opPrefix = TPSEngine.OP_ENROLL_PREFIX;
        else
            opPrefix = TPSEngine.OP_PIN_RESET_PREFIX;

        userCred = requestUserId(op, cuid, userAuth, beginMsg.getExtensions());
        userid = (String) userCred.get(userAuth.getAuthCredName());
        CMS.debug(method + op + " userCred (attempted) userid=" + userid);
        tokenRecord.setUserID(userid);
        authToken = authenticateUser(op, userAuth, userCred);
        userid = authToken.getInString("userid");

        tokenRecord.setUserID(userid);
        CMS.debug(method + " auth token userid=" + userid);
    }

    /**
     * authenticateUser authenticates a user using specified authentication
     *
     * @param op "enrollment", "format", or "pinReset" //TODO: for tokendb activity log
     * @param userAuth the authenticator
     * @param userCred IAuthCredentials obtained from a successful requestUserId call
     * @return IAuthToken information relating to the performed authentication
     *         -- plugin-specific
     */
    public IAuthToken authenticateUser(
            String op,
            TPSAuthenticator userAuth,
            IAuthCredentials userCred)
            throws EBaseException, TPSException {

        String logMsg = null;
        CMS.debug("TPSProcessor.authenticateUser");
        if (op.isEmpty() || userAuth == null || userCred == null) {
            logMsg = "TPSProcessor.authenticateUser: missing parameter(s): op, userAuth, or userCred";
            CMS.debug(logMsg);
            throw new EBaseException(logMsg);
        }
        IAuthManager auth = userAuth.getAuthManager();

        try {
            // Authenticate user
            authToken = auth.authenticate(userCred);
            if (authToken != null) {
                CMS.debug("TPSProcessor.authenticateUser: authentication success");
                Enumeration<String> n = authToken.getElements();
                while (n.hasMoreElements()) {
                    String name = n.nextElement();
                    CMS.debug("TPSProcessor.authenticateUser: got authToken val name:" + name);
                }
                return authToken;
            } else {
                CMS.debug("TPSProcessor.authenticateUser: authentication failure with authToken null");
                throw new TPSException("TPS error user authentication failed.",
                        TPSStatus.STATUS_ERROR_LOGIN);
            }
        } catch (EBaseException e) {
            CMS.debug("TPSProcessor.authenticateUser: authentication failure:" + e);
            throw new TPSException("TPS error user authentication failed.",
                    TPSStatus.STATUS_ERROR_LOGIN);
        }
    }

    /**
     * requestUserId sends message to client to request for user credential
     * per authentication plugin
     *
     * @param op "enrollment", "format", or "pinReset" //TODO: for tokendb activity log
     * @param cuid token CUID //TODO: for tokendb activity log
     * @param extensions message extensions
     * @return IAuthCredentials containing user credential needed for authentication
     */
    IAuthCredentials requestUserId(String op, String cuid, TPSAuthenticator auth, Map<String, String> extensions)
            throws IOException, TPSException, EBaseException {
        CMS.debug("TPSProcessor.requestUserId");
        if (op.isEmpty() ||
                cuid.isEmpty() || auth == null) {
            CMS.debug("TPSProcessor.requestUserId: missing parameter(s): op, cuid, or auth");
            throw new EBaseException("TPSProcessor.requestUserId: missing parameter(s): op, cuid, or auth");
        }

        IAuthCredentials login;
        if (extensions != null &&
                extensions.get("extendedLoginRequest") != null) {
            // default locale will be "en"
            String locale = extensions.get("locale");
            if (extensions.get("locale") == null) {
                locale = "en";
            }
            // title
            String title = auth.getUiTitle(locale);
            if (title.isEmpty())
                title = auth.getUiTitle("en");
            // description
            String description = auth.getUiDescription(locale);
            if (description.isEmpty())
                description = auth.getUiTitle("en");
            // parameters
            HashMap<String, AuthUIParameter> authParamSet = auth.getUiParamSet();
            Set<String> params = new HashSet<String>();
            for (Map.Entry<String, AuthUIParameter> entry : authParamSet.entrySet()) {
                params.add(auth.getUiParam(entry.getKey()).toString(locale));
                CMS.debug("TPSProcessor.requestUserId: for extendedLoginRequest, added param: " +
                        auth.getUiParam(entry.getKey()).toString(locale));
            }

            login = requestExtendedLogin(0 /* invalid_pw */, 0 /* blocked */,
                    params, title, description, auth);
        } else {
            login = requestLogin(0 /* invalid_pw */, 0 /* blocked */, auth);
        }

        return login;
    }

    /**
     * mapCredFromMsgResponse fills up authManager required auth credentials
     * with mapped values from client
     * configuration example:
     *
     * auths.instance.ldap1.ui.id.UID.credMap.msgCred.extlogin=UID
     * auths.instance.ldap1.ui.id.UID.credMap.msgCred.login=screen_name
     * auths.instance.ldap1.ui.id.UID.credMap.authCred=uid
     *
     * auths.instance.ldap1.ui.id.PASSWORD.credMap.msgCred.extlogin=PASSWORD
     * auths.instance.ldap1.ui.id.PASSWORD.credMap.msgCred.login=password
     * auths.instance.ldap1.ui.id.PASSWORD.credMap.authCred=pwd
     *
     * @param response the message response to be mapped
     * @param auth the authentication for mapping consultation
     * @return IAuthCredentials auth credential for auth manager
     */
    public IAuthCredentials mapCredFromMsgResponse(TPSMessage response, TPSAuthenticator auth, boolean extendedLogin)
            throws EBaseException {
        CMS.debug("TPSProcessor.mapCredFromMsgResponse");
        if (response == null || auth == null) {
            CMS.debug("TPSProcessor.mapCredFromMsgResponse: missing parameter(s): response or auth");
            throw new EBaseException("TPSProcessor.mapCredFromMsgResponse: missing parameter(s): response or auth");
        }
        IAuthCredentials login =
                new com.netscape.certsrv.authentication.AuthCredentials();

        String[] requiredCreds = auth.getAuthManager().getRequiredCreds();
        for (String cred : requiredCreds) {
            String name = auth.getCredMap(cred, extendedLogin);
            CMS.debug("TPSProcessor.mapCredFromMsgResponse: cred=" + cred + " &name=" +
                    name);
            login.set(cred, response.get(name));
        }

        return login;
    }

    /**
     * Requests login ID and password from user.
     */
    public IAuthCredentials requestExtendedLogin(int invalidPW, int blocked,
            Set<String> parameters,
            String title,
            String description,
            TPSAuthenticator auth)
            throws IOException, TPSException, EBaseException {

        CMS.debug("TPSProcessor.requestExtendedLogin");
        if (parameters == null || title.isEmpty() ||
                description.isEmpty() || auth == null) {
            CMS.debug("TPSProcessor.requestExtendedLogin: missing parameter(s): parameters, title, description, or auth");
            throw new EBaseException(
                    "TPSProcessor.requestExtendedLogin: missing parameter(s): parameters, title, description, or auth");
        }
        ExtendedLoginRequestMsg loginReq =
                new ExtendedLoginRequestMsg(invalidPW, blocked, parameters, title, description);

        try {
            session.write(loginReq);
        } catch (IOException e) {
            CMS.debug("TPSProcessor.requestExtendedLogin failed WriteMsg: " + e.toString());
            throw e;
        }
        CMS.debug("TPSProcessor.requestExtendedLogin: extendedLoginRequest sent");

        ExtendedLoginResponseMsg loginResp = null;
        try {
            loginResp = (ExtendedLoginResponseMsg) session.read();
        } catch (IOException e) {
            CMS.debug("TPSProcessor.requestExtendedLogin failed ReadMsg: " + e.toString());
            throw e;
        }

        IAuthCredentials login = mapCredFromMsgResponse(loginResp, auth, true /*extendedLogin*/);

        return login;
    }

    /**
     * Requests login ID and password from user.
     */
    public IAuthCredentials requestLogin(int invalidPW, int blocked,
            TPSAuthenticator auth)
            throws IOException, TPSException, EBaseException {

        CMS.debug("TPSProcessor.requestLogin");
        if (auth == null) {
            CMS.debug("TPSProcessor.requestLogin: missing parameter(s): parameters, title, description, or auth");
            throw new EBaseException(
                    "TPSProcessor.requestLogin: missing parameter(s): parameters, title, description, or auth");
        }
        LoginRequestMsg loginReq = new LoginRequestMsg(invalidPW, blocked);

        try {
            session.write(loginReq);
        } catch (IOException e) {
            CMS.debug("TPSProcessor.requestLogin failed WriteMsg: " + e.toString());
            throw e;
        }
        CMS.debug("TPSProcessor.requestLogin: loginRequest sent");

        LoginResponseMsg loginResp = null;
        try {
            loginResp = (LoginResponseMsg) session.read();
        } catch (IOException e) {
            CMS.debug("TPSProcessor.requestLogin failed ReadMsg: " + e.toString());
            throw e;
        }

        IAuthCredentials login = mapCredFromMsgResponse(loginResp, auth, false /*not extendedLogin*/);
        return login;
    }

    /*
     * fillTokenRecord -
     *     - retrieves token record from tokendb if it exists, or
     *     - creates a new token record
     *     this in-memory copy of tokenRecord is to be set in the TPSSession
     */
    protected void fillTokenRecord(TokenRecord tokenRecord, AppletInfo appletInfo)
            throws TPSException {
        String method = "TPSProcessor.fillTokenRecord";
        CMS.debug(method + ": begins");
        if (tokenRecord == null || appletInfo == null) {
            CMS.debug(method + ": params tokenRecord and appletInfo cannot be null");
            throw new TPSException(
                    method + ": missing parameter(s): parameter appletInfo");
        }

        byte app_major_version = appletInfo.getAppMajorVersion();
        byte app_minor_version = appletInfo.getAppMinorVersion();
        TPSBuffer build_id = null;
        try {
            build_id = getAppletVersion();
        } catch (IOException e) {
            CMS.debug(method + ": failed getting applet version:" + e + " ... continue");
        }
        if (build_id != null) {
            tokenRecord.setAppletID(Integer.toHexString(app_major_version) + "."
                    + Integer.toHexString(app_minor_version) + "." +
                    build_id.toHexStringPlain());
        }

        CMS.debug(method + ": ends");

    }

    protected TokenRecord isTokenRecordPresent(AppletInfo appletInfo) throws TPSException {

        if (appletInfo == null) {
            throw new TPSException("TPSProcessor.isTokenRecordPresent: invalid input data.");
        }

        CMS.debug("TPSProcessor.isTokenRecordPresent: " + appletInfo.getCUIDhexString());

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        TokenRecord tokenRecord = null;
        try {
            tokenRecord = tps.tdb.tdbGetTokenEntry(appletInfo.getCUIDhexStringPlain());
            // now the in memory tokenRecord is replaced by the actual token data
            CMS.debug("TPSProcessor.isTokenRecordPresent: found token...");
        } catch (Exception e) {
            CMS.debug("TPSProcessor.isTokenRecordPresent: token does not exist in tokendb... create one in memory");
        }

        return tokenRecord;
    }

    protected String getCAConnectorID() throws TPSException {
        return getCAConnectorID(null, null);
    }

    /*
     * @param enrollType "keyGen" or "renewal"
     * @param keyType e.g. "authentication", "auth", "encryption", or "signing"
     */
    protected String getCAConnectorID(String enrollType, String keyType)
            throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        String id = null;
        String config = null;
        String method = "TPSProcessor.getCAConnectorID:";

        if ((keyType != null) && (enrollType != null)) {
            config = "op." + currentTokenOperation + "." +
                selectedTokenType + "." +
                enrollType + "." +
                keyType+
                ".ca.conn";
            CMS.debug(method + " finding config: " + config);
        } else {
            config = TPSEngine.OP_FORMAT_PREFIX + "." +
                selectedTokenType +
                ".ca.conn";
            CMS.debug(method + " finding config: " + config);
        }

        try {
            id = configStore.getString(config);
        } catch (EBaseException e) {
            throw new TPSException(method + " Internal error finding config value:" + config);

        }

        CMS.debug(method + " returning: " + id);

        return id;
    }

    /*
     * revokeCertsAtFormat returns a boolean that tells if config wants to revoke certs on the token during format
     */
    protected boolean revokeCertsAtFormat() {
        String method = "revokeCertsAtFormat";
        String logMsg;
        CMS.debug(method + ": begins");

        IConfigStore configStore = CMS.getConfigStore();
        String configName = TPSEngine.OP_FORMAT_PREFIX + "." + selectedTokenType + ".revokeCert";
        boolean revokeCert = false;
        try {
            CMS.debug(method + ": getting config:" + configName);
            revokeCert = configStore.getBoolean(configName, false);
        } catch (EBaseException e) {
            logMsg = method + ": config not found: " + configName +
                    "; default to false";
            CMS.debug(logMsg);
        }
        if (!revokeCert) {
            logMsg = method + ":  revokeCert = false";
            CMS.debug(logMsg);
        }
        return revokeCert;
    }

    protected RevocationReason getRevocationReasonAtFormat() {
        String method = "getRevocationReasonAtFormat";
        String logMsg;

        IConfigStore configStore = CMS.getConfigStore();
        String configName = TPSEngine.OP_FORMAT_PREFIX + "." + selectedTokenType + ".revokeCert.reason";
        CMS.debug(method + " finding config: " + configName);

        RevocationReason revokeReason = RevocationReason.UNSPECIFIED;
        try {
            int revokeReasonInt = configStore.getInteger(configName);
            revokeReason = RevocationReason.fromInt(revokeReasonInt);
        } catch (EBaseException e) {
            logMsg = method + ": config not found: " + configName +
                    "; default to unspecified";
            CMS.debug(logMsg);
            revokeReason = RevocationReason.UNSPECIFIED;
        }

        return revokeReason;
    }

    /*
     * revokeCertificates revokes certificates on the token specified
     * @param cuid the cuid of the token to revoke certificates
     * @throws TPSException in case of error
     *
     * TODO: maybe make this a callback function later
     */
    protected void revokeCertificates(String cuid, RevocationReason revokeReason, String caConnId) throws TPSException {
        String logMsg = "";
        final String method = "TPSProcessor.revokeCertificates";

        if (cuid == null) {
            logMsg = "cuid null";
            CMS.debug(method + ":" + logMsg);
            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
        }
        CMS.debug(method + ": begins for cuid:" + cuid);
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        boolean isTokenPresent = tps.tdb.isTokenPresent(cuid);
        if (!isTokenPresent) {
            logMsg = method + ": token not found: " + cuid;
            CMS.debug(logMsg);
            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
        }

        CARemoteRequestHandler caRH = null;
        try {
            caRH = new CARemoteRequestHandler(caConnId);
        } catch (EBaseException e) {
            logMsg = method + ": getting CARemoteRequestHandler failure";
            CMS.debug(logMsg);
            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
        }
        //find all certs belonging to the token
        Collection<TPSCertRecord> certRecords = tps.tdb.tdbGetCertRecordsByCUID(cuid);

        CMS.debug(method + ": found " + certRecords.size() + " certs");

        for (TPSCertRecord cert : certRecords) {
            if (cert.getStatus().equals("revoked")) {
                // already revoked cert should not be on token any more
                CMS.debug(method + ": cert " + cert.getSerialNumber()
                        + " already revoked; remove from tokendb and move on");
                try {
                    tps.certDatabase.removeRecord(cert.getId());
                } catch (Exception e) {
                    logMsg = method + ": removeRecord failed";
                    CMS.debug(logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
                }
                continue;
            }

            String origin = cert.getOrigin();
            if (origin != null && !origin.equals(cuid)) {
                /*
                 * Raidzilla Bug #57803:
                 * If the certificate is not originally created for this
                 * token, we should not revoke the certificate here.
                 * To figure out if this certificate is originally created
                 * for this token, we check the tokenOrigin attribute.
                 */
                CMS.debug(method + ": cert " + cert.getSerialNumber()
                        + " originally created for this token: " + origin +
                        " while current token: " + cuid
                        + "; Remove from tokendb and skip the revoke");
                try {
                    tps.certDatabase.removeRecord(cert.getId());
                } catch (Exception e) {
                    logMsg = method + ": removeRecord failed";
                    CMS.debug(logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
                }
                continue;
            }
            if (origin == null) {
                // no tokenOrigin, then don't care, keep going
                CMS.debug(method + ": tokenOrigin is not present in tokendb cert record");
            }

            // revoke the cert
            /*
             * if the certificates are revoked_on_hold, don't do anything because the certificates may
             * be referenced by more than one token.
             */
            if (cert.getStatus().equals(TokenCertStatus.ONHOLD.toString())) {
                CMS.debug(method + ": cert " + cert.getSerialNumber()
                        + " has status revoked_on_hold; remove from tokendb and move on");
                try {
                    tps.certDatabase.removeRecord(cert.getId());
                } catch (Exception e) {
                    logMsg = method + ": removeRecord failed";
                    CMS.debug(logMsg);
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
                }
                continue;
            }

            String hexSerial = cert.getSerialNumber();
            if (hexSerial.length() >= 3 && hexSerial.startsWith("0x")) {
                String serial = hexSerial.substring(2); // skip over the '0x'
                BigInteger bInt = new BigInteger(serial, 16);
                String serialStr = bInt.toString();
                CMS.debug(method + ": found cert hex serial: " + serial +
                        " dec serial:" + serialStr);
                try {
                    CARevokeCertResponse response = caRH.revokeCertificate(true, serialStr, cert.getCertificate(),
                            revokeReason);
                    CMS.debug(method + ": response status =" + response.getStatus());
                    auditRevoke(cuid, true, revokeReason.getCode(), String.valueOf(response.getStatus()), serialStr,
                            caConnId, null);
                } catch (EBaseException e) {
                    logMsg = method + ": revokeCertificate from CA failed:" + e;
                    CMS.debug(logMsg);
                    auditRevoke(cuid, true, revokeReason.getCode(), "failure", serialStr, caConnId, null);

                    if (revokeReason == RevocationReason.CERTIFICATE_HOLD) {
                        tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, session.getTokenRecord(),
                                session.getIpAddress(), logMsg,
                                "failure");
                    } else {
                        tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, session.getTokenRecord(),
                                session.getIpAddress(), logMsg,
                                "failure");
                    }
                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
                }
            } else {
                logMsg = "mulformed hex serial number :" + hexSerial;
                CMS.debug(method + ": " + logMsg);
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, session.getTokenRecord(), session.getIpAddress(),
                        logMsg,
                        "failure");
                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_REVOKE_CERTIFICATES_FAILED);
            }
            logMsg = "Certificate " + hexSerial + " revoked";
            tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, session.getTokenRecord(), session.getIpAddress(), logMsg,
                    "success");

            // delete cert from tokendb
            CMS.debug(method + ": cert " + cert.getSerialNumber()
                    + ": remove from tokendb");
            try {
                tps.certDatabase.removeRecord(cert.getId());
            } catch (Exception e) {
                logMsg = "removeRecord failed:" + e;
                CMS.debug(method + ": " + logMsg);
                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_UPDATE_TOKENDB_FAILED);
            }
            continue;
        }
        CMS.debug(method + ": done for cuid:" + cuid);
    }

    /*
     * allow global policy  for externalReg to set in config whether invalid certs are allowed
     * to be recovered on token
     * Invalid certs are:
     *  - revoked certs
     *  - expired certs
     *  - certs not yet valid
     */
    public boolean allowRecoverInvalidCert() throws TPSException {
        String method = "TPSProcessor.allowRecoverInvalidCert:";
        boolean ret = true;
        IConfigStore configStore = CMS.getConfigStore();
        String configName = "externalReg.allowRecoverInvalidCert.enable";
        try {
            ret = configStore.getBoolean(configName, true);
        } catch (EBaseException e) {
            throw new TPSException(method + e.getMessage() , TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }
        return ret;
    }

    /*
     * processExternalRegAttrs :
     * - retrieve from authToken relevant attributes for externalReg
     * - parse the multi-valued attributes
     * @returns ExternalRegAttrs
     */
    ExternalRegAttrs processExternalRegAttrs(/*IAuthToken authToken,*/String authId) throws NumberFormatException, EBaseException {
        String method = "processExternalRegAttrs";
        String configName;
        String tVal;
        String[] vals;
        ExternalRegAttrs erAttrs = new ExternalRegAttrs(authId);
        IConfigStore configStore = CMS.getConfigStore();

        CMS.debug(method + ": getting from authToken:"
                + erAttrs.ldapAttrNameTokenType);
        vals = authToken.getInStringArray(erAttrs.ldapAttrNameTokenType);
        if (vals == null) {
            // get the default externalReg tokenType
            configName = "externalReg.default.tokenType";
            tVal = configStore.getString(configName,
                    "externalRegAddToToken");
            CMS.debug(method + ": set default tokenType:" + tVal);
            erAttrs.setTokenType(tVal);
        } else {
            CMS.debug(method + ": retrieved tokenType:" + vals[0]);
            erAttrs.setTokenType(vals[0]);
        }

        CMS.debug(method + ": getting from authToken:"
                + erAttrs.ldapAttrNameTokenCUID);
        vals = authToken.getInStringArray(erAttrs.ldapAttrNameTokenCUID);
        if (vals != null) {
            CMS.debug(method + ": retrieved cuid:" + vals[0]);
            erAttrs.setTokenCUID(vals[0]);
        }

        /*
         * certs to be recovered for this user
         *     - multi-valued
         */
        CMS.debug(method + ": getting from authToken:"
                + erAttrs.ldapAttrNameCertsToRecover);
        vals = authToken.getInStringArray(erAttrs.ldapAttrNameCertsToRecover);
        if (vals != null) {
            // if any cert is mis-configured, the whole thing will bail
            for (String val : vals) {
                CMS.debug(method + ": retrieved certsToRecover:" + val);
                /*
                 * Each cert is represented as
                 *    (serial#, caID, keyID, kraID)
                 * e.g.
                 *    (1234, ca1, 81, kra1)
                 *    note: numbers above are in decimal
                 *    note: if keyID is less than or equal to 0, then recovery will be done by cert
                 *          otherwise recovery is done by keyID
                 *    note: if it only contains the serial# and caID (missing keyID and kraID)
                 *          then it is used for retaining certs already existing on token
                 */
                String[] items = val.split(",");
                if (items.length !=2 && items.length !=4)
                    throw new EBaseException(method + ": certsToRecover format error");
                ExternalRegCertToRecover erCert =
                        new ExternalRegCertToRecover();
                int i = 0;
                for (i = 0; i < items.length; i++) {
                    if (i == 0) {
                        CMS.debug(method + "setting serial: " + items[i]);
                        erCert.setSerial(new BigInteger(items[i]));
                    } else if (i == 1)
                        erCert.setCaConn(items[i]);
                    else if (i == 2) {
                        CMS.debug(method + "setting keyid: " + items[i]);
                        erCert.setKeyid(new BigInteger(items[i]));
                    } else if (i == 3)
                        erCert.setKraConn(items[i]);
                }
                if (i<3) {
                    erCert.setIsRetainable(true);
                }
                erAttrs.addCertToRecover(erCert);
            }
        } else {
            CMS.debug(method + ": certsToRecover attribute " + erAttrs.ldapAttrNameCertsToRecover +
                    " not found");
        }

        /*
         * certs to be deleted for this user
         *     - multi-valued
         * TODO: decide if we need CertsToDelete or not
         *
        CMS.debug(method + ": getting from authToken:"
                + erAttrs.ldapAttrNameCertsToDelete);
        vals = authToken.getInStringArray(erAttrs.ldapAttrNameCertsToDelete);
        if (vals != null) {
            for (String val : vals) {
                CMS.debug(method + ": retrieved certsToDelete:" + val);

                //  Each cert is represented as
                //     (serial#, caID, revokeOnDelete)
                //  e.g.
                //     (234, ca1, true)
                //     note: number above is in decimal

                String[] items = val.split(",");
                ExternalRegCertToDelete erCert =
                        new ExternalRegCertToDelete();
                for (int i = 0; i < items.length; i++) {
                    if (i == 0)
                        erCert.setSerial(new BigInteger(items[i]));
                    else if (i == 1)
                        erCert.setCaConn(items[i]);
                    else if (i == 2) {
                        if (items[i].equals("true"))
                            erCert.setRevoke(true);
                        else
                            erCert.setRevoke(false);
                    }
                }
                erAttrs.addCertsToDelete(erCert);
            }
        }
        */

        return erAttrs;
    }

    protected void setExternalRegSelectedTokenType(ExternalRegAttrs erAttrs)
            throws TPSException {
        String method = "TPSProcessor.setExternalRegSelectedTokenType: ";
        IConfigStore configStore = CMS.getConfigStore();
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);

        CMS.debug(method + " begins");
        if (erAttrs == null || erAttrs.getTokenType() == null) {
            // get the default externalReg tokenType
            String configName = "externalReg.default.tokenType";
            CMS.debug(method + "erAttrs null or externalReg user entry does not contain tokenType...setting to default config: "
                    + configName);
            try {
                String tokenType = configStore.getString(configName,
                        "externalRegAddToToken");
                CMS.debug(method + " setting tokenType to default:" +
                        tokenType);
                setSelectedTokenType(tokenType);
            } catch (EBaseException e) {
                CMS.debug(method + " Internal Error obtaining mandatory config values. Error: "
                        + e);
                String logMsg = "TPS error getting config values from config store." + e.toString();
                tps.tdb.tdbActivity(currentTokenOperation, session.getTokenRecord(), session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
        } else {
            CMS.debug(method + " setting tokenType to tokenType attribute of user entry:"
                    +
                    erAttrs.getTokenType());
            setSelectedTokenType(erAttrs.getTokenType());
        }
    }

    protected void format(boolean skipAuth) throws TPSException, IOException {

        IConfigStore configStore = CMS.getConfigStore();
        String configName = null;
        String logMsg = null;
        String appletVersion = null;

        CMS.debug("TPSProcessor.format begins");
        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);

        AppletInfo appletInfo = null;
        TokenRecord tokenRecord = null;
        try {
            appletInfo = getAppletInfo();
            auditOpRequest("format", appletInfo, "success", null);
        } catch (TPSException e) {
            logMsg = e.toString();
            // appletInfo is null as expected at this point
            // but audit for the record anyway
            auditOpRequest("format", appletInfo, "failure", logMsg);
            tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw e;
        }
        appletInfo.setAid(getCardManagerAID());

        CMS.debug("TPSProcessor.format: token cuid: " + appletInfo.getCUIDhexStringPlain());
        boolean isTokenPresent = false;

        tokenRecord = isTokenRecordPresent(appletInfo);

        if (tokenRecord != null) {
            CMS.debug("TPSProcessor.format: found token...");
            isTokenPresent = true;
        } else {
            CMS.debug("TPSProcessor.format: token does not exist in tokendb... create one in memory");
            tokenRecord = new TokenRecord();
            tokenRecord.setId(appletInfo.getCUIDhexStringPlain());
        }

        fillTokenRecord(tokenRecord, appletInfo);
        session.setTokenRecord(tokenRecord);

        String cuid = appletInfo.getCUIDhexString();
        CMS.debug("TPSProcessor.format: CUID hex string=" + appletInfo.getCUIDhexStringPlain());
        //tokenRecord.setId(appletInfo.getCUIDhexString(true));
        String msn = appletInfo.getMSNString();

        byte major_version = appletInfo.getMajorVersion();
        byte minor_version = appletInfo.getMinorVersion();
        byte app_major_version = appletInfo.getAppMajorVersion();
        byte app_minor_version = appletInfo.getAppMinorVersion();

        CMS.debug("TPSProcessor.format: major_version " + major_version + " minor_version: " + minor_version
                + " app_major_version: " + app_major_version + " app_minor_version: " + app_minor_version);

        String tokenType = "tokenType";

        IAuthCredentials userCred =
                new com.netscape.certsrv.authentication.AuthCredentials();
        if (isExternalReg) {
            CMS.debug("In TPSProcessor.format isExternalReg: ON");
            /*
              need to reach out to the Registration DB (authid)
              Entire user entry should be retrieved and parsed, if needed
              The following are retrieved:
                  externalReg.tokenTypeAttributeName=tokenType
                  externalReg.certs.recoverAttributeName=certsToRecover
             */
            /*
             * - tokenType id NULL at this point for isExternalReg
             * - loginRequest cannot be per profile(tokenType) for isExternalReg
             *   because of the above; now it is per instance:
             *     "externalReg.format.loginRequest.enable"
             *     "externalReg.default.tokenType"
             *   it is not enabled by default.
             */
            configName = "externalReg.format.loginRequest.enable";
            boolean requireLoginRequest;
            try {
                requireLoginRequest = configStore.getBoolean(configName, false);
            } catch (EBaseException e) {
                CMS.debug("TPSProcessor.format: Internal Error obtaining mandatory config values. Error: " + e);
                logMsg = "TPS error getting config values from config store." + e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
            if (!requireLoginRequest) {
                CMS.debug("In TPSProcessor.format: no Login required");
                // get the default externalReg tokenType
                configName = "externalReg.default.tokenType";
                try {
                    tokenType = configStore.getString(configName,
                            "externalRegAddToToken");
                    setSelectedTokenType(tokenType);
                } catch (EBaseException e) {
                    CMS.debug("TPSProcessor.format: Internal Error obtaining mandatory config values. Error: " + e);
                    logMsg = "TPS error getting config values from config store." + e.toString();
                    tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                            "failure");

                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
                }
                CMS.debug("In TPSProcessor.format: isExternalReg: setting tokenType to default first:" +
                        tokenType);
            } else {
                /* get user login and password - set in "login" */
                CMS.debug("In TPSProcessor.format: isExternalReg: calling requestUserId");
                configName = "externalReg.authId";
                String authId;
                try {
                    authId = configStore.getString(configName);
                } catch (EBaseException e) {
                    CMS.debug("TPSProcessor.format: Internal Error obtaining mandatory config values. Error: " + e);
                    logMsg = "TPS error getting config values from config store." + e.toString();
                    tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                            "failure");

                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
                }
                TPSAuthenticator userAuth = null;
                try {
                    userAuth = getAuthentication(authId);

                    processAuthentication(TPSEngine.FORMAT_OP, userAuth, cuid, tokenRecord);
                    auditAuth(userid, currentTokenOperation, appletInfo, "success", authId);
                } catch (Exception e) {
                    auditAuth(userid, currentTokenOperation, appletInfo, "failure",
                            (userAuth != null) ? userAuth.getID() : null);
                    // all exceptions are considered login failure
                    CMS.debug("TPSProcessor.format:: authentication exception thrown: " + e);
                    logMsg = "authentication failed, status = STATUS_ERROR_LOGIN";

                    tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                            "failure");

                    throw new TPSException(logMsg,
                            TPSStatus.STATUS_ERROR_LOGIN);
                }

                ExternalRegAttrs erAttrs;
                try {
                    erAttrs = processExternalRegAttrs(/*authToken,*/authId);
                } catch (Exception ee) {
                    logMsg = "processExternalRegAttrs: " + ee.toString();
                    tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                            "failure");

                    throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
                }
                session.setExternalRegAttrs(erAttrs);
                /* test
                ArrayList<ExternalRegCertToRecover> erCertsToRecover =
                session.getExternalRegAttrs().getCertsToRecover();

                for (ExternalRegCertToRecover erCert : erCertsToRecover) {
                    BigInteger serial = erCert.getSerial();
                    CMS.debug("In TPSProcessor.format: " + "serial: " + serial.toString());
                    BigInteger keyid = erCert.getKeyid();
                    if (keyid != null)
                        CMS.debug("In TPSProcessor.format: " + "keyid: " + keyid.toString());
                    else
                        CMS.debug("In TPSProcessor.format: " + "no keyid");
                }
                test ends */

                setExternalRegSelectedTokenType(erAttrs);
//                setSelectedTokenType(erAttrs.getTokenType());
            }
            CMS.debug("In TPSProcessor.format: isExternalReg: about to process keySet resolver");
            /*
             * Note: externalReg.mappingResolver=none indicates no resolver
             *    plugin used
             */
            try {
            String resolverInstName = getKeySetResolverInstanceName();

                if (!resolverInstName.equals("none") && (selectedKeySet == null)) {
                    FilterMappingParams mappingParams = createFilterMappingParams(resolverInstName,
                            appletInfo.getCUIDhexStringPlain(), appletInfo.getMSNString(),
                            appletInfo.getMajorVersion(), appletInfo.getMinorVersion());
                    TPSSubsystem subsystem =
                            (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
                    BaseMappingResolver resolverInst =
                            subsystem.getMappingResolverManager().getResolverInstance(resolverInstName);
                    String keySet = resolverInst.getResolvedMapping(mappingParams, "keySet");
                    setSelectedKeySet(keySet);
                    CMS.debug("In TPSProcessor.format: resolved keySet: " + keySet);
                }
            } catch (TPSException e) {
                logMsg = e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
        } else {
            CMS.debug("In TPSProcessor.format isExternalReg: OFF");
            /*
             * Note: op.format.tokenProfileResolver=none indicates no resolver
             *    plugin used (tokenType resolved perhaps via authentication)
             */

            try {
                String resolverInstName = getResolverInstanceName();

                if (!resolverInstName.equals("none") && (selectedKeySet == null)) {
                    FilterMappingParams mappingParams  = createFilterMappingParams(resolverInstName, appletInfo.getCUIDhexStringPlain(), msn, major_version, minor_version);

                    TPSSubsystem subsystem =
                            (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
                    BaseMappingResolver resolverInst =
                            subsystem.getMappingResolverManager().getResolverInstance(resolverInstName);
                    tokenType = resolverInst.getResolvedMapping(mappingParams);
                    setSelectedTokenType(tokenType);
                    CMS.debug("In TPSProcessor.format: resolved tokenType: " + tokenType);
                }
            } catch (TPSException e) {
                logMsg = e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
            CMS.debug("TPSProcessor.format: calculated tokenType: " + tokenType);
        }

        // isExternalReg : user already authenticated earlier
        if (!isExternalReg) {
            // authenticate per profile/tokenType configuration
            configName = TPSEngine.OP_FORMAT_PREFIX + "." + tokenType + ".auth.enable";
            boolean isAuthRequired;
            try {
                CMS.debug("TPSProcessor.format: getting config: " + configName);
                isAuthRequired = configStore.getBoolean(configName, true);
            } catch (EBaseException e) {
                String info = " Internal Error obtaining mandatory config values. Error: " + e;
                auditFormat(userid, appletInfo, "failure",
                        null, info);
                CMS.debug("TPSProcessor.format: " + info);
                logMsg = "TPS error: " + info;
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }

            if (isAuthRequired && !skipAuth) {
                TPSAuthenticator userAuth = null;
                try {
                    userAuth = getAuthentication(TPSEngine.OP_FORMAT_PREFIX, tokenType);
                    processAuthentication(TPSEngine.FORMAT_OP, userAuth, cuid, tokenRecord);
                    auditAuth(userid, currentTokenOperation, appletInfo, "success",
                            (userAuth != null) ? userAuth.getID() : null);
                } catch (Exception e) {
                    auditAuth(userid, currentTokenOperation, appletInfo, "failure",
                            (userAuth != null) ? userAuth.getID() : null);
                    // all exceptions are considered login failure
                    CMS.debug("TPSProcessor.format:: authentication exception thrown: " + e);
                    logMsg = "authentication failed, status = STATUS_ERROR_LOGIN";

                    tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                            "failure");

                    throw new TPSException(logMsg,
                            TPSStatus.STATUS_ERROR_LOGIN);
                }
            } // TODO: if no auth required, should wipe out existing tokenRecord entry data later?
        }

        //Now check provided profile
        checkProfileStateOK();

        if (isTokenPresent) {
            CMS.debug("TPSProcessor.format: token exists");
            TokenStatus newState = TokenStatus.FORMATTED;
            // Check for transition to FORMATTED status.

            if (!tps.isOperationTransitionAllowed(tokenRecord, newState)) {
                String info = " illegal transition attempted: " + tokenRecord.getTokenStatus() +
                        " to " + newState;
                CMS.debug("TPSProcessor.format: token transition: " + info);
                logMsg = "Operation for CUID " + appletInfo.getCUIDhexStringPlain() + " Disabled. " + info;
                auditFormat(userid, appletInfo, "failure",
                        null, info);

                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");

                throw new TPSException(logMsg,
                        TPSStatus.STATUS_ERROR_DISABLED_TOKEN);
            } else {
                CMS.debug("TPSProcessor.format: token transition allowed " +
                        tokenRecord.getTokenStatus() +
                        " to " + newState);
            }
        } else {
            checkAllowUnknownToken(TPSEngine.OP_FORMAT_PREFIX);

            tokenRecord.setTokenStatus(TokenStatus.UNFORMATTED);
            CMS.debug("TPSProcessor.format: token does not exist");
            logMsg = "add token during format";
            try {
                tps.tdb.tdbAddTokenEntry(tokenRecord, TokenStatus.UNFORMATTED);
                tps.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord, session.getIpAddress(), logMsg, "success");
                CMS.debug("TPSProcessor.format: token added");
            } catch (Exception e) {
                logMsg = logMsg + ":" + e.toString();
                tps.tdb.tdbActivity(ActivityDatabase.OP_ADD, tokenRecord, session.getIpAddress(), logMsg,
                        "failure");
                throw new TPSException(logMsg);
            }

        }

        // TODO: the following lines of code could be replaced with call to
        // checkAndUpgradeApplet()
        TPSBuffer build_id = getAppletVersion();

        if (build_id == null) {
            checkAllowNoAppletToken(TPSEngine.OP_FORMAT_PREFIX);
        } else {
            appletVersion = formatCurrentAppletVersion(appletInfo);
        }

        String appletRequiredVersion = checkForAppletUpgrade(TPSEngine.OP_FORMAT_PREFIX);

        CMS.debug("TPSProcessor.format: appletVersion found: " + appletVersion + " requiredVersion: "
                + appletRequiredVersion);

        String tksConnId = getTKSConnectorID();

        upgradeApplet(appletInfo,TPSEngine.OP_FORMAT_PREFIX, appletRequiredVersion,
                beginMsg.getExtensions(), tksConnId,
                10, 90);
        CMS.debug("TPSProcessor.format: Completed applet upgrade.");


        // Add issuer info to the token

        writeIssuerInfoToToken(null,appletInfo);

        if (requiresStatusUpdate()) {
            statusUpdate(100, "PROGRESS_DONE");
        }

        // Upgrade Symm Keys if needed

        SecureChannel channel;
        try {
            channel = checkAndUpgradeSymKeys(appletInfo, tokenRecord);
        } catch (TPSException te) {
            auditKeyChangeover(appletInfo, "failure", null /* TODO */,
                    getSymmetricKeysRequiredVersionHexString(), te.toString());
            throw te;
        }
        channel.externalAuthenticate();

        auditFormat(userid, appletInfo, "success", channel.getKeyInfoData().toHexStringPlain(), null);

        if (isTokenPresent && revokeCertsAtFormat()) {
            // Revoke certificates on token, if so configured
            RevocationReason reason = getRevocationReasonAtFormat();
            String caConnId = getCAConnectorID();

            try {
                revokeCertificates(tokenRecord.getId(), reason, caConnId);
            } catch (TPSException te) {
                // failed revocation; capture message and continue
                String failMsg = "revoke certificates failure";
                logMsg = failMsg + ":" + te.toString();
                CMS.debug("TPSProcessor.format: " + logMsg);
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
            } catch (Exception ee) {
                String failMsg = "revoke certificates failure";
                logMsg = failMsg + ":" + ee.toString();
                CMS.debug("TPSProcessor.format: " + logMsg);
                tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");
                throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
            }
        }

       try {
            // clean up the cert records used to belong to this token in tokendb
            tps.tdb.tdbRemoveCertificatesByCUID(tokenRecord.getId());
        } catch (Exception e) {
            logMsg = "Attempt to clean up record with tdbRemoveCertificatesByCUID failed; token probably clean; continue anyway:"
                    + e;
            CMS.debug("TPSProcessor.format: " + logMsg);
        }

        // Update Token DB
        tokenRecord.setTokenStatus(TokenStatus.FORMATTED);
        logMsg = "token format operation";
        try {
            tps.tdb.tdbUpdateTokenEntry(tokenRecord);
            tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg, "success");
        } catch (Exception e) {
            logMsg = logMsg + ":" + e.toString();
            tps.tdb.tdbActivity(ActivityDatabase.OP_FORMAT, tokenRecord, session.getIpAddress(), logMsg,
                    "failure");

            throw new TPSException(logMsg, TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }

        CMS.debug("TPSProcessor.format:: ends");

    }

    protected void writeIssuerInfoToToken(SecureChannel origChannel,AppletInfo appletInfo) throws TPSException, IOException,
            UnsupportedEncodingException {
        if (checkIssuerInfoEnabled()) {

            String tksConnId = getTKSConnectorID();

            int defKeyIndex = getChannelDefKeyIndex();
            int defKeyVersion = getChannelDefKeyVersion();

            SecureChannel channel = null;

            if (origChannel != null) {
                channel = origChannel;
            } else {

                channel = setupSecureChannel((byte) defKeyVersion, (byte) defKeyIndex, tksConnId,appletInfo);
                channel.externalAuthenticate();

            }

            String issuer = getIssuerInfoValue();

            // We know this better be ASCII value URL.
            byte[] issuer_bytes = issuer.getBytes("US-ASCII");
            TPSBuffer issuerInfoBuff = new TPSBuffer(issuer_bytes);

            channel.setIssuerInfo(issuerInfoBuff);

        }
    }

    protected String getResolverInstanceName() throws TPSException {

        CMS.debug("TPSProcessor.getResolverInstanceName: entering for operaiton : " + currentTokenOperation);
        IConfigStore configStore = CMS.getConfigStore();
        String resolverInstName = null;

        String opPrefix = null;
        String opDefault = null;

        if (currentTokenOperation.equals(TPSEngine.FORMAT_OP)) {
            opPrefix = TPSEngine.OP_FORMAT_PREFIX;
            opDefault = TPSEngine.CFG_DEF_FORMAT_PROFILE_RESOLVER;

        } else if (currentTokenOperation.equals(TPSEngine.ENROLL_OP)) {
            opDefault = TPSEngine.CFG_DEF_ENROLL_PROFILE_RESOLVER;
            opPrefix = TPSEngine.OP_ENROLL_PREFIX;
        } else if (currentTokenOperation.equals(TPSEngine.PIN_RESET_OP)) {

            opDefault = TPSEngine.CFG_DEF_PIN_RESET_PROFILE_RESOLVER;
            opPrefix = TPSEngine.OP_PIN_RESET_PREFIX;
        } else {
            throw new TPSException(
                    "TPSProcessor.getResolverInstanceName: Invalid operation type, can not calculate resolver instance!",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        String config = opPrefix +
                "." + TPSEngine.CFG_MAPPING_RESOLVER;

        CMS.debug("TPSProcessor.getResolverInstanceName: config: " + config);
        try {
            resolverInstName = configStore.getString(config, opDefault);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getResolverInstanceName: Internal error finding config value.");

        }

        CMS.debug("TPSProcessor.getResolverInstanceName: returning: " + resolverInstName);

        return resolverInstName;
    }

    protected String getKeySetResolverInstanceName() throws TPSException {
        String method = "TPSProcessor.getKeySetResolverInstanceName: ";
        CMS.debug(method + " begins");
        IConfigStore configStore = CMS.getConfigStore();
        String resolverInstName = null;

        if (!isExternalReg) {
            CMS.debug(method + "externalReg not enabled; keySet mapping currently only supported in externalReg.");
            return null;
        }
        String config = "externalReg" +
                "." + TPSEngine.CFG_MAPPING_RESOLVER;

        CMS.debug(method + " config: " + config);
        try {
            resolverInstName = configStore.getString(config, "none");
        } catch (EBaseException e) {
            throw new TPSException(e.getMessage());
        }
        if (resolverInstName.equals(""))
            resolverInstName = "none";

        CMS.debug(method + " returning: " + resolverInstName);

        return resolverInstName;
    }

    /**
     * @param resolverInstName
     * @param cuid
     * @param msn
     * @param major_version
     * @param minor_version
     * @return
     */
    protected FilterMappingParams createFilterMappingParams(
            String resolverInstName,
            String cuid,
            String msn,
            byte major_version,
            byte minor_version)
            throws TPSException {
        String method = "TPSProcessor.createFilterMappingParams: ";
        FilterMappingParams mappingParams = new FilterMappingParams();


            try {
                mappingParams = new FilterMappingParams();
                CMS.debug(method + " after new MappingFilterParams");
                mappingParams.set(FilterMappingParams.FILTER_PARAM_MAJOR_VERSION,
                        String.valueOf(major_version));
                mappingParams.set(FilterMappingParams.FILTER_PARAM_MINOR_VERSION,
                        String.valueOf(minor_version));
                mappingParams.set(FilterMappingParams.FILTER_PARAM_CUID, cuid);
                mappingParams.set(FilterMappingParams.FILTER_PARAM_MSN, msn);
                // fill in the extensions from client, if any
                if (beginMsg.getExtensions() != null) {
                    mappingParams.set(FilterMappingParams.FILTER_PARAM_EXT_TOKEN_TYPE,
                            beginMsg.getExtensions().get("tokenType"));
                    mappingParams.set(FilterMappingParams.FILTER_PARAM_EXT_TOKEN_ATR,
                            beginMsg.getExtensions().get("tokenATR"));
                    mappingParams.set(FilterMappingParams.FILTER_PARAM_EXT_KEY_SET,
                            beginMsg.getExtensions().get("keySet"));
                }
                CMS.debug(method + " MappingFilterParams set");

            } catch (Exception et) {
                CMS.debug(method + " exception:" + et);
                throw new TPSException(method + " failed.",
                        TPSStatus.STATUS_ERROR_MAPPING_RESOLVER_FAILED);
            }

        return mappingParams;
    }

    protected String getIssuerInfoValue() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        String info = null;

        String config = "op." + currentTokenOperation + "." + selectedTokenType + "." + TPSEngine.CFG_ISSUER_INFO_VALUE;

        CMS.debug("TPSProcessor.getIssuerInfoValue: config: " + config);
        try {
            info = configStore.getString(config, null);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getIssuerInfoValue: Internal error finding config value.");

        }

        if (info == null) {
            throw new TPSException("TPSProcessor.getIssuerInfoValue: Can't find issuer info value in the config.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        CMS.debug("TPSProcessor.getIssuerInfoValue: returning: " + info);

        return info;
    }

    void checkProfileStateOK() throws TPSException {

        CMS.debug("TPSProcessor.checkProfileStateOK()");

        String profileState = null;
        try {
            profileState = profileDatabase.getRecordStatus(selectedTokenType);
        } catch (EBaseException e) {
            //Default TPSException will return a "contact admin" error code.
            throw new TPSException(
                    "TPSProcessor.checkProfileStateOK: internal error in getting profile state from config.");
        }

        if (!profileState.equals(Constants.CFG_ENABLED)) {
            CMS.debug("TPSProcessor.checkProfileStateOK: profile specifically disabled.");
            throw new TPSException("TPSProcessor.checkProfileStateOK: profile disabled!");
        }

    }

    protected boolean checkIssuerInfoEnabled() throws TPSException {

        CMS.debug("TPSProcessor.checkIssuerEnabled entering...");

        IConfigStore configStore = CMS.getConfigStore();

        String issuerEnabledConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_ISSUER_INFO_ENABLE;

        CMS.debug("TPSProcessor.checkIssuerEnabled config to check: " + issuerEnabledConfig);

        boolean issuerInfoEnabled = false;

        try {
            issuerInfoEnabled = configStore.getBoolean(issuerEnabledConfig, false);
        } catch (EBaseException e) {
            //Default TPSException will return a "contact admin" error code.
            throw new TPSException(
                    "TPSProcessor.checkIssuerInfo: internal error in getting value from config.");
        }

        CMS.debug("TPSProcessor.checkIssuerEnabled returning: " + issuerInfoEnabled);
        return issuerInfoEnabled;

    }

    //Obtain value and set class property.
    protected void checkIsExternalReg() throws TPSException {

        IConfigStore configStore = CMS.getConfigStore();
        String External_Reg_Cfg = TPSEngine.CFG_EXTERNAL_REG + "." + "enable";

        try {
            //These defaults are well known, it is safe to use them.

            CMS.debug("In TPS_Processor.checkIsExternalReg.");

            this.isExternalReg = configStore.getBoolean(External_Reg_Cfg, false);
            CMS.debug("In TPS_Processor.checkIsExternalReg. isExternalReg: " + isExternalReg);
        } catch (EBaseException e1) {
            CMS.debug("TPS_Processor.checkIsExternalReg: Internal Error obtaining mandatory config values. Error: "
                    + e1);
            throw new TPSException("TPS error getting config values from config store.");
        }

    }

    boolean checkServerSideKeyGen(String connId) throws TPSException {

        boolean result;
        IConfigStore configStore = CMS.getConfigStore();

        String profileConfig = "conn." + connId + "." + ".serverKeygen";

        try {
            result = configStore.getBoolean(profileConfig, false);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor: checkServerSideKeyGen: Internal error obtaining config value!");
        }

        return result;
    }

    void checkAllowNoAppletToken(String operation) throws TPSException {
        boolean allow = true;
        IConfigStore configStore = CMS.getConfigStore();

        String noAppletConfig = operation + "." + selectedTokenType + "." + TPSEngine.CFG_ALLOW_NO_APPLET;

        try {
            allow = configStore.getBoolean(noAppletConfig, true);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.checkAllowNoAppletToken: Internal error getting config param.");
        }

        if (!allow) {
            throw new TPSException("TPSProcessor.checkAllowNoAppletToken: token without applet not permitted!",
                    TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }

    }

    boolean checkForAppletUpdateEnabled() throws TPSException {
        boolean enabled = false;

        IConfigStore configStore = CMS.getConfigStore();

        String appletUpdate = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_UPDATE_APPLET_ENABLE;
        CMS.debug("TPSProcessor.checkForAppletUpdateEnabled: getting config: " + appletUpdate);
        try {
            enabled = configStore.getBoolean(appletUpdate, false);
        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSProcessor.checkForAppleUpdateEnabled: Can't find applet Update Enable. Internal error obtaining value.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }
        CMS.debug("TPSProcessor.checkForAppletUpdateEnabled: returning " + enabled);
        return enabled;
    }

    protected String checkForAppletUpgrade(String operation) throws TPSException {
        String requiredVersion = null;
        IConfigStore configStore = CMS.getConfigStore();

        String appletRequiredConfig = operation + "." + selectedTokenType + "."
                + TPSEngine.CFG_APPLET_UPDATE_REQUIRED_VERSION;
        CMS.debug("TPSProcessor.checkForAppletUpgrade: getting config: " + appletRequiredConfig);
        try {
            requiredVersion = configStore.getString(appletRequiredConfig, null);
        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSProcessor.checkForAppletUpgrade: Can't find applet required Version. Internal error obtaining version.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        if (requiredVersion == null) {
            throw new TPSException("TPSProcessor.checkForAppletUpgrade: Can't find applet required Version.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        CMS.debug("TPSProcessor.checkForAppletUpgrade: returning: " + requiredVersion);

        return requiredVersion;
    }

    protected void checkAllowUnknownToken(String operation) throws TPSException {
        boolean allow = true;

        IConfigStore configStore = CMS.getConfigStore();

        String unknownConfig = "op." + operation + "." + TPSEngine.CFG_ALLOW_UNKNOWN_TOKEN;

        try {
            allow = configStore.getBoolean(unknownConfig, true);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.checkAllowUnknownToken: Internal error getting config value.");
        }

        if (allow == false) {
            throw new TPSException(
                    "TPSProcessor.checkAllowUnknownToken: Unknown tokens not allowed for this operation!",
                    TPSStatus.STATUS_ERROR_TOKEN_DISABLED);
        }

    }

    protected String getTKSConnectorID() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        String id = null;

        String config = "op." + currentTokenOperation + "." + selectedTokenType + ".tks.conn";

        try {
            id = configStore.getString(config, "tks1");
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getTKSConnectorID: Internal error finding config value.");

        }

        CMS.debug("TPSProcessor.getTKSConectorID: returning: " + id);

        return id;
    }

    protected TPSBuffer getNetkeyAID() throws TPSException {

        String NetKeyAID = null;
        IConfigStore configStore = CMS.getConfigStore();
        try {

            NetKeyAID = configStore.getString(TPSEngine.CFG_APPLET_NETKEY_INSTANCE_AID,
                    TPSEngine.CFG_DEF_NETKEY_INSTANCE_AID);

        } catch (EBaseException e1) {
            CMS.debug("TPS_Processor.getNetkeyAID: Internal Error obtaining mandatory config values. Error: " + e1);
            throw new TPSException("TPS error getting config values from config store.");
        }

        TPSBuffer ret = new TPSBuffer(NetKeyAID);

        return ret;
    }

    protected TPSBuffer getNetkeyPAID() throws TPSException {

        String NetKeyPAID = null;
        IConfigStore configStore = CMS.getConfigStore();
        try {

            NetKeyPAID = configStore.getString(
                    TPSEngine.CFG_APPLET_NETKEY_FILE_AID, TPSEngine.CFG_DEF_NETKEY_FILE_AID);

        } catch (EBaseException e1) {
            CMS.debug("TPS_Processor.getNetkeyAID: Internal Error obtaining mandatory config values. Error: " + e1);
            throw new TPSException("TPS error getting config values from config store.");
        }

        TPSBuffer ret = new TPSBuffer(NetKeyPAID);

        return ret;
    }

    protected TPSBuffer getCardManagerAID() throws TPSException {

        String cardMgrAID = null;
        IConfigStore configStore = CMS.getConfigStore();
        try {

            cardMgrAID = configStore.getString(TPSEngine.CFG_APPLET_CARDMGR_INSTANCE_AID,
                    TPSEngine.CFG_DEF_CARDMGR_INSTANCE_AID);

        } catch (EBaseException e1) {
            CMS.debug("TPS_Processor.getNetkeyAID: Internal Error obtaining mandatory config values. Error: " + e1);
            throw new TPSException("TPS error getting config values from config store.");
        }

        TPSBuffer ret = new TPSBuffer(cardMgrAID);

        return ret;
    }

    protected String getAppletExtension() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        String extension = null;
        String extensionConfig = TPSEngine.CFG_APPLET_EXTENSION;

        try {
            extension = configStore.getString(extensionConfig, "ijc");
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getAppletExtension: Internal error finding config value.");

        }

        CMS.debug("TPSProcessor.getAppletExtension: returning: " + extension);

        return extension;
    }

    protected String getAppletDirectory(String operation) throws TPSException {

        IConfigStore configStore = CMS.getConfigStore();
        String directory = null;

        String directoryConfig = operation + "." + selectedTokenType + "." + TPSEngine.CFG_APPLET_DIRECTORY;

        //We need a directory
        try {
            directory = configStore.getString(directoryConfig);
        } catch (EPropertyNotFound e) {
            throw new TPSException("TPSProcessor.getAppletDirectory: Required config param missing.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getAppletDirectory: Internal error finding config value.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        CMS.debug("getAppletDirectory: returning: " + directory);
        return directory;
    }

    protected int getChannelBlockSize() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int blockSize = 0;
        try {
            blockSize = configStore.getInteger(TPSEngine.CFG_CHANNEL_BLOCK_SIZE, TPSEngine.CFG_CHANNEL_DEF_BLOCK_SIZE);

        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getChannelBlockSize: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        CMS.debug("TPSProcess.getChannelBlockSize: returning: " + blockSize);
        return blockSize;

    }

    protected int getChannelInstanceSize() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int instanceSize = 0;
        try {
            instanceSize = configStore.getInteger(TPSEngine.CFG_CHANNEL_INSTANCE_SIZE,
                    TPSEngine.CFG_CHANNEL_DEF_INSTANCE_SIZE);

        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getChannelInstanceSize: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        CMS.debug("TPSProcess.getChannelInstanceSize: returning: " + instanceSize);

        return instanceSize;

    }

    protected int getAppletMemorySize() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int memSize = 0;
        try {
            memSize = configStore.getInteger(TPSEngine.CFG_CHANNEL_APPLET_MEMORY_SIZE,
                    TPSEngine.CFG_CHANNEL_DEF_APPLET_MEMORY_SIZE);

        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getAppletMemorySize: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }
        CMS.debug("TPSProcess.getAppletMemorySize: returning: " + memSize);

        return memSize;
    }

    protected int getChannelDefKeyVersion() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int ver = 0;
        try {
            ver = configStore.getInteger(TPSEngine.CFG_CHANNEL_DEFKEY_VERSION, 0x0);

        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getChannelDefKeyVersion: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        CMS.debug("TPSProcessor.getChannelDefKeyVersion: " + ver);

        return ver;

    }

    protected int getChannelDefKeyIndex() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int index = 0;
        try {
            index = configStore.getInteger(TPSEngine.CFG_CHANNEL_DEFKEY_INDEX, 0x0);

        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getChannelDefKeyIndex: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        CMS.debug("TPSProcessor.getChannelDefKeyIndex: " + index);

        return index;

    }

    protected String getSharedSecretTransportKeyName(String connId) throws TPSException {

        IConfigStore configStore = CMS.getConfigStore();
        String sharedSecretName = null;
        try {
            String configName = "conn." + connId + ".tksSharedSymKeyName";
            sharedSecretName = configStore.getString(configName, "sharedSecret");

        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getSharedSecretTransportKey: Internal error finding config value: "
                    + e,
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

        }

        CMS.debug("TPSProcessor.getSharedSecretTransportKeyName: calculated key name: " + sharedSecretName);

        return sharedSecretName;

    }
    protected PK11SymKey getSharedSecretTransportKey(String connId) throws TPSException, NotInitializedException {


        String sharedSecretName = getSharedSecretTransportKeyName(connId);

        CMS.debug("TPSProcessor.getSharedSecretTransportKey: calculated key name: " + sharedSecretName);

        String symmKeys = null;
        boolean keyPresent = false;

        try {
            symmKeys = SessionKey.ListSymmetricKeys("internal");
            CMS.debug("TPSProcessor.getSharedSecretTransportKey: symmKeys List: " + symmKeys);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            CMS.debug(e);
        }

        for (String keyName : symmKeys.split(",")) {
            if (sharedSecretName.equals(keyName)) {
                CMS.debug("TPSProcessor.getSharedSecret: shared secret key found!");
                keyPresent = true;
                break;
            }

        }

        if (!keyPresent) {
            throw new TPSException("TPSProcessor.getSharedSecret: Can't find shared secret!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        // We know for now that shared secret is on this token
        String tokenName = "Internal Key Storage Token";
        PK11SymKey sharedSecret = SessionKey.GetSymKeyByName(tokenName, sharedSecretName);

        CMS.debug("TPSProcessor.getSharedSecret: SymKey returns: " + sharedSecret);

        return sharedSecret;

    }

    public boolean getIsExternalReg() {
        return isExternalReg;
    }

    public void process(BeginOpMsg beginMsg) throws TPSException, IOException {

        if (beginMsg == null) {
            throw new TPSException("TPSProcessor.process: invalid input data, not beginMsg provided.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }
        setBeginMessage(beginMsg);
        setCurrentTokenOperation("format");
        checkIsExternalReg();

        format(false);
    }

    public void statusUpdate(int status, String info) throws IOException {

        if (!requiresStatusUpdate())
            return;

        CMS.debug("In TPSProcessor.statusUpdate status: " + status + " info: " + info);

        StatusUpdateRequestMsg statusUpdate = new StatusUpdateRequestMsg(status, info);
        session.write(statusUpdate);

        //We don't really care about the response, just that we get it.

        session.read();

    }

    public TPSEngine getTPSEngine() {
        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);

        return subsystem.getEngine();

    }

    // Do the incoming extensions support status update?
    public boolean requiresStatusUpdate() {

        boolean result = false;

        // We can't get here without a begin message established.
        String update = getBeginMessage().getExtension(BeginOpMsg.STATUS_UPDATE_EXTENSION_NAME);

        if (update != null && update.equals("true")) {
            result = true;
        }

        return result;

    }

    protected AppletInfo getAppletInfo() throws TPSException, IOException {
        AppletInfo result = null;

        CMS.debug("TPSProcessor.getAppletInfo, entering ...");

        selectCardManager();

        TPSBuffer cplc_data = getCplcData();
        CMS.debug("cplc_data: " + cplc_data.toHexString());

        TPSBuffer token_cuid = extractTokenCUID(cplc_data);
        TPSBuffer token_msn = extractTokenMSN(cplc_data);

        /**
         * Checks if the netkey has the required applet version.
         */

        selectCoolKeyApplet();

        TPSBuffer token_status = getStatus();

        byte major_version = 0x0;
        byte minor_version = 0x0;
        byte app_major_version = 0x0;
        byte app_minor_version = 0x0;

        CMS.debug("TPS_Processor.getAppletInfo: status: " + token_status.toHexString());
        if (token_status.size() >= 4) {
            major_version = token_status.at(0);
            minor_version = token_status.at(1);
            app_major_version = token_status.at(2);
            app_minor_version = token_status.at(3);
        }

        int free_mem = 0;
        int total_mem = 0;

        if (token_status.size() >= 12) {
            byte tot_high = token_status.at(6);
            byte tot_low = token_status.at(7);

            byte free_high = token_status.at(10);
            byte free_low = token_status.at(11);

            total_mem = (tot_high << 8) + tot_low;
            free_mem = (free_high << 8) + free_low;

        }

        result = new AppletInfo(major_version, minor_version, app_major_version, app_minor_version);
        result.setCUID(token_cuid);
        result.setMSN(token_msn);
        result.setTotalMem(total_mem);
        result.setFreeMem(free_mem);

        CMS.debug("TPSProcessor.getAppletInfo: cuid: " + result.getCUIDhexString() + " msn: " + result.getMSNString()
                + " major version: " + result.getMajorVersion() + " minor version: " + result.getMinorVersion()
                + " App major version: " + result.getAppMajorVersion() + " App minor version: "
                + result.getAppMinorVersion());

        String currentAppletVersion = formatCurrentAppletVersion(result);
        if (currentAppletVersion != null) {
            CMS.debug("TPSProcessor.getAppletInfo: current applet version = " +
                currentAppletVersion);
        }

        return result;
    }

    protected void selectCardManager() throws TPSException, IOException {
        CMS.debug("TPSProcessor.selectCardManager: entering..");
        TPSBuffer aidBuf = getCardManagerAID();

        APDUResponse select = selectApplet((byte) 0x04, (byte) 0x00, aidBuf);

        if (!select.checkResult()) {
            throw new TPSException("TPSProcessor.selectCardManager: Can't selelect the card manager applet!");
        }
    }



    protected boolean checkSymmetricKeysEnabled() throws TPSException {
        boolean result = true;

        IConfigStore configStore = CMS.getConfigStore();

        String symmConfig = "op" + "." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_SYMM_KEY_UPGRADE_ENABLED;

        try {
            result = configStore.getBoolean(symmConfig, true);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.checkSymmetricKeysEnabled: Internal error getting config value.");
        }

        return result;
    }

    protected int getSymmetricKeysRequiredVersion() throws TPSException {
        int version = 0;
        ;

        IConfigStore configStore = CMS.getConfigStore();

        String requiredVersionConfig = "op" + "." + currentTokenOperation + "." + selectedTokenType + "."
                + "update.symmetricKeys.requiredVersion";

        CMS.debug("TPSProcessor.getSymmetricKeysRequiredVersion: configValue: " + requiredVersionConfig);
        try {
            version = configStore.getInteger(requiredVersionConfig, 0x0);
        } catch (EBaseException e) {
            throw new TPSException("TPSProcessor.getSymmetricKeysRequired: Internal error getting config value.");
        }

        CMS.debug("TPSProcessor.getSymmetricKeysRequiredVersion: returning version: " + version);

        return version;
    }

    protected String getSymmetricKeysRequiredVersionHexString() throws TPSException {
        int requiredVersion = getSymmetricKeysRequiredVersion();
        byte[] nv = { (byte) requiredVersion, 0x01 };
        TPSBuffer newVersion = new TPSBuffer(nv);
        String newVersionStr = newVersion.toHexString();
        return newVersionStr;
    }

    protected SecureChannel checkAndUpgradeSymKeys(AppletInfo appletInfo,TokenRecord tokenRecord) throws TPSException, IOException {

        /* If the key of the required version is
          not found, create them.

          This sends a InitializeUpdate request to the token.
          We tell the token to use whatever it thinks is the
          default key version (0). It will return the version
          of the key it actually used later. (This is accessed
          with GetKeyInfoData below)
          [ Note: This is not explained very well in the manual
            The token can have multiple sets of symmetric keys
            Each set is given a version number, which I think is
            better thought of as a SLOT. One key slot is populated
            with a set of keys when the token is manufactured.
            This is then designated as the default key set version.
            Later, we will write a new key set with PutKey, and
            set it to be the new default]
        */

        if(tokenRecord == null || appletInfo == null) {
            throw new TPSException("TPSProcessor.checkAndUpgradeSymKeys: invalid input data!");
        }

        SecureChannel channel = null;

        int defKeyVersion = 0;
        int defKeyIndex = getChannelDefKeyIndex();

        if (checkSymmetricKeysEnabled()) {

            CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: Symm key upgrade enabled.");
            int requiredVersion = getSymmetricKeysRequiredVersion();

            // try to make a secure channel with the 'requiredVersion' keys
            // If this fails, we know we will have to attempt an upgrade
            // of the keys

            boolean failed = false;
            try {

                channel = setupSecureChannel((byte) requiredVersion, (byte) defKeyIndex,
                        getTKSConnectorID(),appletInfo);

            } catch (TPSException e) {

                CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: failed to create secure channel with required version, we need to upgrade the keys.");
                failed = true;
            }

            //If we failed we need to upgrade the keys
            if (failed == true) {

                selectCardManager();

                channel = setupSecureChannel(appletInfo);

                auditKeyChangeoverRequired(appletInfo,
                        channel.getKeyInfoData().toHexStringPlain(),
                        getSymmetricKeysRequiredVersionHexString(), null);

                /* Assemble the Buffer with the version information
                 The second byte is the key offset, which is always 1
                */

                byte[] nv = { (byte) requiredVersion, 0x01 };
                TPSBuffer newVersion = new TPSBuffer(nv);

                // GetKeyInfoData will return a buffer which is bytes 11,12 of
                // the data structure on page 89 of Cyberflex Access Programmer's
                // Guide
                // Byte 0 is the key set version.
                // Byte 1 is the index into that key set

                String connId = getTKSConnectorID();
                TPSBuffer curKeyInfo = channel.getKeyInfoData();
                TPSEngine engine = getTPSEngine();

                int protocol = 1;
                if (channel.isSCP02()) {
                    protocol = 2;
                }

                //Sanity checking

                boolean cuidOK = checkCUIDMatchesKDD(appletInfo.getCUIDhexStringPlain(), appletInfo.getKDDhexStringPlain());
                boolean isVersionInRange = checkCardGPKeyVersionIsInRange(appletInfo.getCUIDhexStringPlain(), appletInfo.getKDDhexStringPlain(), curKeyInfo.toHexStringPlain());
                boolean doesVersionMatchTokenDB = checkCardGPKeyVersionMatchesTokenDB(appletInfo.getCUIDhexStringPlain(), appletInfo.getKDDhexStringPlain(), curKeyInfo.toHexStringPlain());

                if(cuidOK == false) {
                    throw new TPSException("TPSProcessor.generateSecureChannel: cuid vs kdd matching policy not met!",
                            TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
                }

                if(isVersionInRange == false) {

                    throw new TPSException("TPSProcessor.generateSecureChannel: key version is not within acceptable range!",
                            TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
                }

                if(doesVersionMatchTokenDB == false) {
                    throw new TPSException("TPSProcessor.generateSecureChannel: key version from token does not match that of the token db!",
                            TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
                }

                TPSBuffer keySetData = engine.createKeySetData(newVersion, curKeyInfo, protocol,
                        appletInfo.getCUID(),channel.getKeyDiversificationData(), channel.getDekSessionKeyWrapped(), connId, getSelectedKeySet());

                //CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: new keySetData from TKS: " + keySetData.toHexString());
                CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: received new keySetData from TKS");

                byte curVersion = curKeyInfo.at(0);
                byte curIndex = curKeyInfo.at(1);

                int done = 0;
                if (done == 1)
                    throw new TPSException("TPSProcessor.checkAndUpgradeSymKeys: end of progress.");

                try {
                    channel.putKeys(curVersion, curIndex, keySetData);
                } catch (TPSException e) {

                    CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: failed to put key, checking to see if this a SCP02 with 0xFF default key set.");

                    if (protocol == 2 && curVersion == (byte) 0xff) {
                        CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: failed to put key, but we have SCP02 and the 0xFF dev key, try again.");

                        byte[] nv_dev = { (byte) 0x1, (byte) 0x1 };
                        TPSBuffer devKeySetData = engine.createKeySetData(new TPSBuffer(nv_dev), curKeyInfo, protocol,
                              appletInfo.getCUID(),  channel.getKeyDiversificationData(), channel.getDekSessionKeyWrapped(), connId, getSelectedKeySet());

                        CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: about to get rid of keyset 0xFF and replace it with keyset 0x1 with developer key set");
                        channel.putKeys((byte) 0x0, (byte) 0x1, devKeySetData);

                        CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: We've only upgraded to the dev key set on key set #01, will have to try again to upgrade to #02");

                    } else {
                        throw e;
                    }

                }

                String curVersionStr = curKeyInfo.toHexString();
                String newVersionStr = newVersion.toHexString();

                //Only change in db if we upgrade, thus we don't need to worry about rolling back on failure.
                //Thus the setting, rollbackKeyVersionOnPutKeyFailure is not needed.

                CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: changing token db keyInfo to: " + newVersion.toHexStringPlain());
                tokenRecord.setKeyInfo(newVersion.toHexStringPlain());

                CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: curVersionStr: " + curVersionStr + " newVersionStr: "
                        + newVersionStr);
                selectCoolKeyApplet();

                channel = setupSecureChannel((byte) requiredVersion, (byte) defKeyIndex,
                        getTKSConnectorID(), appletInfo);
                auditKeyChangeover(appletInfo, "success", curVersionStr, newVersionStr, null);

            } else {
                CMS.debug("TPSProcessor.checkAndUpgradeSymeKeys: We are already at the desired key set, returning secure channel.");
            }

           // tokenRecord.setKeyInfo(channel.getKeyInfoData().toHexStringPlain());

        } else {
            //Create a standard secure channel with current key set.
            CMS.debug("TPSProcessor.checkAndUpgradeSymKeys: Key changeover disabled in the configuration.");

            defKeyVersion = getChannelDefKeyVersion();

            channel = setupSecureChannel((byte) defKeyVersion, (byte) defKeyIndex,
                    getTKSConnectorID(),appletInfo);

        }

        CMS.debug("TPSProcessor.checkAndUpdradeSymKeys: Leaving successfully....");
        return channel;
    }

    //List objects that may be on a given token
    //Return null if object void of objects

    protected TPSBuffer listObjects(byte seq) throws TPSException, IOException {
        TPSBuffer objects = null;

        ListObjectsAPDU listObjects = new ListObjectsAPDU(seq);

        APDUResponse respApdu = handleAPDURequest(listObjects);

        if (!respApdu.checkResult()) {
            CMS.debug("TPSProcessor.listObjects: Bad response from ListObjects! Token possibly has no objects");
            return null;
        }

        objects = respApdu.getData();

        return objects;

    }

    // Request new pin from client
    protected String requestNewPin(int minLen, int maxLen) throws IOException, TPSException {

        CMS.debug("TPSProcessor.requestNewPin: entering...");

        String newPin = null;

        NewPinRequestMsg new_pin_req = new NewPinRequestMsg(minLen, maxLen);

        session.write(new_pin_req);

        NewPinResponseMsg new_pin_resp = (NewPinResponseMsg) session.read();

        newPin = new_pin_resp.get(NewPinResponseMsg.NEW_PIN_NAME);

        if (newPin.length() < minLen || newPin.length() > maxLen) {
            throw new TPSException("TPSProcessor.requestNewPin: new pin length outside of length contraints: min: "
                    + minLen + " max: " + maxLen);
        }

        return newPin;
    }

    /*
     * mapPattern maps pattern with $...$ tokens
     * e.g.
     * dnpattern=cn=$auth.firstname$.$auth.lastname$,e=$auth.mail$,o=Example Org
     *   where from ldap,
     *       value of firstname is John
     *       value of lastname is Doe
     *       value of mail is JohnDoe@EXAMPLE.org
     *   then the returned value will be:
     *       John.Doe,e=JohnDoe@EXAMPLE.org,o=Example Org
     *
     */
    protected String mapPattern(LinkedHashMap<String, String> map, String inPattern) throws TPSException {

        String result = "";

        if (inPattern == null || map == null) {
            throw new TPSException("TPSProcessor.mapPattern: Illegal input paramters!",
                    TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }

        final char delim = '$';
        String pattern = inPattern;

        /*
         * Outer (while) loop searches for next token (in the format of $xxx$) to be mapped
         *   when a pattern is found
         *     inner (for) loop goes through all mappable params that the token maps to
         */
        while (true) {
            String patternToMap = null;
            int firstPos = 0;
            int nextPos = 0;
            CMS.debug("TPSProcessor.mapPattern: pattern =" + pattern);
            String patternMapped = "";
            firstPos = pattern.indexOf(delim);
            if (firstPos == -1) {
                //no more token
                break;
            }
            nextPos = pattern.indexOf(delim, firstPos + 1);

            if ((nextPos - firstPos) <= 1) {
                //  return pattern;
                break; // no more pattern to match
            }

            patternToMap = pattern.substring(firstPos + 1, nextPos);

            //CMS.debug("TPSProcessor.mapPattern: patternTo map: " + patternToMap);

            String piece1 = "";
            if (firstPos >= 1)
                piece1 = pattern.substring(0, firstPos);

            String piece2 = "";
            if (nextPos < (pattern.length() - 1))
                piece2 = pattern.substring(nextPos + 1);

            for (Map.Entry<String, String> entry : map.entrySet()) {
                String key = entry.getKey();

                String value = entry.getValue();
                //CMS.debug("TPSProcessor.mapPattern: Exposed: key: " + key + " Param: " + value);

                if (key.equalsIgnoreCase(patternToMap)) {
                    CMS.debug("TPSProcessor.mapPattern: found match: key: " + key + " mapped to: " + value);
                    patternMapped = value;
                    //CMS.debug("TPSProcessor.mapPattern: pattern mapped: " + patternMapped);
                    break;
                }

            }

            // if patternMapped wasn't mapped, it will be ""
            result = (piece1 + patternMapped + piece2);
            pattern = result;
        }

        if (result.equals("")) {
            CMS.debug("TPSProcessor.mapPattern: returning: " + inPattern);
            return (inPattern);
        } else {
            CMS.debug("TPSProcessor.mapPattern: returning: " + result);
            return result;
        }

    }

    protected String formatCurrentAppletVersion(AppletInfo aInfo) throws TPSException, IOException {
        String method = "TPSProcessor.formatCurrentAppletVersion: ";
        CMS.debug(method + " begins");
        /*
         * TODO: looks like calling formatCurrentAppletVersion() more than
         * once will cause keygen to fail on token. (resolve later if needed)
         * In the mean time, resolution is to save up the result the first
         *  time it is called
         */

        if (aInfo == null) {
            throw new TPSException("TPSProcessor.formatCurrentAppletVersion: ", TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }

        if (aInfo.getFinalAppletVersion() != null) {
            return aInfo.getFinalAppletVersion();
        }

        TPSBuffer build_id = getAppletVersion();
        if (build_id == null) {
            CMS.debug(method + " getAppletVersion returning null");
            return null;
        }
        String build_idStr = build_id.toHexStringPlain();

        String finalVersion = aInfo.getAppMajorVersion() + "." + aInfo.getAppMinorVersion() + "." + build_idStr;

        finalVersion = finalVersion.toLowerCase();

        aInfo.setFinalAppletVersion(finalVersion);
        CMS.debug(method + " returing: " + finalVersion);

        return finalVersion;

    }

    protected void checkAndHandlePinReset(SecureChannel channel) throws TPSException, IOException {

        CMS.debug("TPSProcessor.checkAndHandlePinReset entering...");

        if (channel == null) {
            throw new TPSException("TPSProcessor.checkAndHandlePinReset: invalid input data!",
                    TPSStatus.STATUS_ERROR_TOKEN_RESET_PIN_FAILED);
        }

        IConfigStore configStore = CMS.getConfigStore();

        String pinResetEnableConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_ENABLE;

        CMS.debug("TPSProcessor.checkAndHandlePinReset config to check: " + pinResetEnableConfig);

        String minLenConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_MIN_LEN;

        CMS.debug("TPSProcessor.checkAndHandlePinReset config to check: " + minLenConfig);

        String maxLenConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_MAX_LEN;

        CMS.debug("TPSProcessor.checkAndHandlePinReset config to check: " + maxLenConfig);

        String maxRetriesConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_MAX_RETRIES;

        CMS.debug("TPSProcessor.checkAndHandlePinReset config to check: " + maxRetriesConfig);

        String pinStringConfig = TPSEngine.CFG_PIN_RESET_STRING;

        CMS.debug("TPSProcessor.checkAndHandlePinReset config to check: " + pinStringConfig);

        boolean enabled = false;
        int minLen;
        int maxLen;
        int maxRetries;
        String stringName;

        try {

            enabled = configStore.getBoolean(pinResetEnableConfig, true);

            if (enabled == false) {
                CMS.debug("TPSProcessor.checkAndHandlePinReset:  Pin Reset not allowed by configuration, exiting...");
                return;

            }

            minLen = configStore.getInteger(minLenConfig, 4);
            maxLen = configStore.getInteger(maxLenConfig, 10);
            maxRetries = configStore.getInteger(maxRetriesConfig, 0x7f);
            stringName = configStore.getString(pinStringConfig, "password");

            CMS.debug("TPSProcessor.checkAndHandlePinReset: config vals: enabled: " + enabled + " minLen: "
                    + minLen + " maxLen: " + maxLen);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSProcessor.checkAndHandlePinReset: internal error in getting value from config.");
        }

        String new_pin = requestNewPin(minLen, maxLen);

        channel.createPin(0x0, maxRetries, stringName);

        channel.resetPin(0x0, new_pin);

    }

    protected void checkAndAuthenticateUser(AppletInfo appletInfo, String tokenType) throws TPSException {
        IAuthCredentials userCred;
        TokenRecord tokenRecord = getTokenRecord();
        String method = "checkAndAuthenticateUser";

        String opPrefix = null;

        if (TPSEngine.ENROLL_OP.equals(currentTokenOperation)) {
            opPrefix = TPSEngine.OP_ENROLL_PREFIX;
        } else if (TPSEngine.FORMAT_OP.equals(currentTokenOperation)) {
            opPrefix = TPSEngine.OP_FORMAT_PREFIX;
        } else {
            opPrefix = TPSEngine.OP_PIN_RESET_PREFIX;
        }

        if (!isExternalReg) {
            // authenticate per profile/tokenType configuration
            String configName = opPrefix + "." + tokenType + ".auth.enable";
            IConfigStore configStore = CMS.getConfigStore();

            TPSSubsystem tps =
                    (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            //TPSSession session = getSession();
            boolean isAuthRequired;
            try {
                CMS.debug("TPSProcessor.checkAndAuthenticateUser: getting config: " + configName);
                isAuthRequired = configStore.getBoolean(configName, true);
            } catch (EBaseException e) {
                CMS.debug("TPSProcessor.checkAndAuthenticateUser: Internal Error obtaining mandatory config values. Error: "
                        + e);
                throw new TPSException("TPS error getting config values from config store.",
                        TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }

            CMS.debug(method + ": opPrefox: " + opPrefix);

            if (isAuthRequired) {
                TPSAuthenticator userAuth = null;
                try {
                    userAuth = getAuthentication(opPrefix, tokenType);
                    processAuthentication(TPSEngine.ENROLL_OP, userAuth, appletInfo.getCUIDhexString(), tokenRecord);
                    auditAuth(userid, currentTokenOperation, appletInfo, "success",
                            (userAuth != null) ? userAuth.getID() : null);

                } catch (Exception e) {
                    // all exceptions are considered login failure
                    auditAuth(userid, currentTokenOperation, appletInfo, "failure",
                            (userAuth != null) ? userAuth.getID() : null);
                    CMS.debug("TPSProcessor.checkAndAuthenticateUser:: authentication exception thrown: " + e);
                    String msg = "TPS error user authentication failed:" + e;
                    tps.tdb.tdbActivity(ActivityDatabase.OP_ENROLLMENT, tokenRecord, session.getIpAddress(), msg,
                            "failure");

                    throw new TPSException(msg,
                            TPSStatus.STATUS_ERROR_LOGIN);
                }
            } else {
                throw new TPSException(
                        "TPSProcessor.checkAndAuthenticateUser: TPS enrollment must have authentication enabled.",
                        TPSStatus.STATUS_ERROR_LOGIN);

            }

        }
    }

    public void acquireChannelPlatformAndProtocolInfo() throws TPSException, IOException {

        if (platProtInfo == null) {
            platProtInfo = new PlatformAndSecChannelProtoInfo();
        } else { // We don't need this any more
            return;
        }

        try {
            gp211GetSecureChannelProtocolDetails();
        } catch (TPSException e) {
            CMS.debug("TPSProcessor.acquireChannelPlatformProtocolInfo: Error getting gp211 protocol data, assume scp01 "
                    + e);
            platProtInfo.setPlatform(SecureChannel.GP201);
            platProtInfo.setProtocol(SecureChannel.SECURE_PROTO_01);

        }

        if (platProtInfo.isGP211() && platProtInfo.isSCP02()) {
            // We only support impl 15, the most common, at this point.

            if (platProtInfo.getImplementation() != SecureChannel.GP211_SCP02_IMPL_15) {
                throw new TPSException(
                        "SecureChannel.acquireChannelPlatformAndProtocolInfo card returning a non supported implementation for SCP02 "
                                + platProtInfo.getImplementation());
            }
        }

    }

    public void gp211GetSecureChannelProtocolDetails() throws TPSException, IOException {
        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: Query card for secure channel protocol details for gp211.");

        TPSBuffer data = null;
        TPSBuffer keyData = null;

        selectCardManager();
        try {

            data = getData(SecureChannel.GP211_GET_DATA_CARD_DATA);
            keyData = getData(SecureChannel.GP211_GET_DATA_KEY_INFO);

        } catch (TPSException e) {
            CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: Card can't understand GP211! " + e);

            throw e;

        }

        if (data.size() < 5) {
            throw new TPSException("TPSProcessor.gp211GetSecureChannelProtocolDetails: invalide return data.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        //CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: returned data: " + data.toHexString());
        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: card data returned");

        // Now process the GP211 data returned by the card.

        int offset = 0;
        int totalLength = 0;
        int length = 0;

        if (data.at(offset) == (byte) 0x66) {
            offset++;

            totalLength = data.getIntFrom1Byte(offset++);
            offset++;

        } else {
            offset++;
            totalLength = data.getIntFrom1Byte(offset++);

        }

        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: totalLength: " + totalLength);

        if (totalLength == 0 || totalLength >= data.size()) {
            throw new TPSException("TPSProcessor.gp211GetSecureChannelProtocolDetails: Invalid return data.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        offset++;

        length = data.getIntFrom1Byte(offset++);

        TPSBuffer oidCardRecognitionData = data.substr(offset, length);

        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: oidCardRecognitionData: "
                + oidCardRecognitionData.toHexString());

        platProtInfo.setOidCardRecognitionData(oidCardRecognitionData);

        offset += length + 2 + 1;

        length = data.getIntFrom1Byte(offset++);

        TPSBuffer oidCardManagementTypeAndVer = data.substr(offset, length);

        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: oidCardManagementTypeAndVer: "
                + oidCardManagementTypeAndVer.toHexString());

        platProtInfo.setOidCardManagementTypeAndVer(oidCardManagementTypeAndVer);

        offset += length + 2 + 1;

        length = data.getIntFrom1Byte(offset++);

        TPSBuffer oidCardIdentificationScheme = data.substr(offset, length);

        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: oidCardIdentificationScheme: "
                + oidCardIdentificationScheme.toHexString());

        platProtInfo.setOidCardIdentificationScheme(oidCardIdentificationScheme);

        offset += length + 2 + 1;

        length = data.getIntFrom1Byte(offset++);

        TPSBuffer oidSecureChannelProtocol = data.substr(offset, length);

        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: oidSecureChannelProtocol: "
                + oidSecureChannelProtocol.toHexString());

        byte protocol = oidSecureChannelProtocol.at(length - 2);
        byte implementation = oidSecureChannelProtocol.at(length - 1);

        if (protocol == SecureChannel.SECURE_PROTO_03) {
            throw new TPSException("TPSProcessor.gp211GetSecureChannelProtocolDetails: No support for SCP03 as of yet, bailing.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        platProtInfo.setProtocol(protocol);
        platProtInfo.setImplementation(implementation);
        platProtInfo.setKeysetInfoData(keyData);

        if (protocol == SecureChannel.SECURE_PROTO_02)
            platProtInfo.setPlatform(SecureChannel.GP211);
        else
            platProtInfo.setPlatform(SecureChannel.GP201);


        CMS.debug("TPSProcessor.gp211GetSecureChannelProtocolDetails: protocol: " + protocol + " implementation: "
                + implementation + " keyInfoData: " + keyData.toHexString());

    }

    public PlatformAndSecChannelProtoInfo getChannelPlatformAndProtocolInfo() {
        return platProtInfo;
    }

    boolean checkCardGPKeyVersionIsInRange(String CUID, String KDD, String keyInfoData) throws TPSException {
        boolean result = true;

        //ToDo : Add Audit messages .


        String method = "checkCardGPKeyVersionIsInRange: ";

        CMS.debug(method + " entering: keyInfoData: " + keyInfoData);

        if (CUID == null || KDD == null || keyInfoData == null) {
            throw new TPSException(method + " Invalid input data!");
        }

        IConfigStore configStore = CMS.getConfigStore();

        String checkBoundedGPKeyVersionConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_ENABLE_BOUNDED_GP_KEY_VERSION;

        CMS.debug(method + " config to check: " + checkBoundedGPKeyVersionConfig);

        try {
            result = configStore.getBoolean(checkBoundedGPKeyVersionConfig, true);
        } catch (EBaseException e) {
            throw new TPSException(
                    method + " error getting config value.");
        }

        CMS.debug(method + " returning: " + result);

        // Check only if asked.

        if (result == true) {

            String minConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                    + TPSEngine.CFG_MINIMUM_GP_KEY_VERSION;
            String maxConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                    + TPSEngine.CFG_MAXIMUM_GP_KEY_VERSION;

            CMS.debug(method + " config to check: minConfig: " + minConfig + " maxConfig: " + maxConfig);

            String maxVersion = null;
            String minVersion = null;

            try {
                minVersion = configStore.getString(minConfig, "01");
                maxVersion = configStore.getString(maxConfig, "FF");
            } catch (EBaseException e) {
                throw new TPSException(
                        method + " error getting config value.");
            }

            if (minVersion.length() != 2 || maxVersion.length() != 2) {
                result = false;
            }

            CMS.debug(method + " minVersion: " + minVersion + " maxVersion: " + maxVersion);

            if (keyInfoData.length() != 4) {
                result = false;
            } else {
                // Actually check the version range;

                String keyInfoVer = keyInfoData.substring(0, 2);

                CMS.debug(method + " Version reported from key Info Data: " + keyInfoVer);

                int versionMinCompare = keyInfoVer.compareToIgnoreCase(minVersion);
                int versionMaxCompare = keyInfoVer.compareToIgnoreCase(maxVersion);

                CMS.debug(method + " versionMinCompare: " + versionMinCompare + " versionMaxCompare: "
                        + versionMaxCompare);

                if (versionMinCompare >= 0 && versionMaxCompare <= 0) {
                    CMS.debug(method + " Version : " + keyInfoVer + " is in range of: " + minVersion + " and: "
                            + maxVersion);
                    result = true;
                } else {
                    result = false;
                    CMS.debug(method + " Version : " + keyInfoVer + " is NOT in range of: " + minVersion + " and: "
                            + maxVersion);
                }
            }

        } else {
            //Configured to ignore, report success.
            result = true;
        }

        CMS.debug(method + " Returning result of: " + result);

        return result;
    }

    boolean checkCUIDMatchesKDD(String CUID, String KDD) throws TPSException {
        boolean result = true;

        String method = "TPsProcessor.checkCUIDMatchesKDD: " ;

        CMS.debug(method + " CUID " + CUID + " KDD: " + KDD);

        if (CUID == null || KDD == null) {
            throw new TPSException(method + " invalid input data!");
        }

        IConfigStore configStore = CMS.getConfigStore();

        String checkCUIDMatchesKDDConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_CUID_MUST_MATCH_KDD;

        CMS.debug(method + " config to check: " + checkCUIDMatchesKDDConfig);

        try {
            result = configStore.getBoolean(checkCUIDMatchesKDDConfig, false);
        } catch (EBaseException e) {
            throw new TPSException(
                    method + " error getting config value.");
        }

        CMS.debug(method + " config result: " + result);

        // Check only if asked to
        if (result == true) {
            if (CUID.compareToIgnoreCase(KDD) == 0) {
                CMS.debug(method + " CUID and KDD values match!");
                result = true;
            } else {
                CMS.debug(method + " CUID and KDD values differ!");
                result = false;
            }
        } else {
            //Configured to ignore, report success.
            result = true;
        }

        CMS.debug(method + " returning result: " + result);

        return result;
    }

    protected String getKeyInfoFromTokenDB(String cuid) throws TPSException {
        String keyInfo = null;

        if (cuid == null) {
            throw new TPSException("TPSProcessor.getKeyInfoFromTokenDB: invalid input data!",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }

        TokenRecord tokenRecord = getTokenRecord();

        keyInfo = tokenRecord.getKeyInfo();

        CMS.debug("TPProcessor.getKeyInfioFromTokenDB: returning: " + keyInfo);

        return keyInfo;

    }

    boolean checkCardGPKeyVersionMatchesTokenDB(String CUID, String KDD,
            String keyInfoData) throws TPSException {

        String method = "checkCardGPKeyVersionMatchesTokenDB: ";

        if(CUID == null || KDD == null || keyInfoData == null) {
            throw new TPSException(method + " Invalid input data!");
        }

        boolean result = true;

        IConfigStore configStore = CMS.getConfigStore();

        String checkValidateVersion = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_VALIDATE_CARD_KEY_INFO_AGAINST_DB;

        CMS.debug(method + " config to check: " + checkValidateVersion);

        try {
            result = configStore.getBoolean(checkValidateVersion, true);
        } catch (EBaseException e) {
            throw new TPSException(
                    method + " error getting config value.");
        }

        CMS.debug(method + " config result: " + result);


        if(result == true) {
            //Check only if asked to.

            String keyInfoInDB = getKeyInfoFromTokenDB(CUID);

            CMS.debug(method + " keyInfoFromTokenDB: " + keyInfoInDB);
            CMS.debug(method + " keyInfoFromToken: " +  keyInfoData);


            if(keyInfoData.compareToIgnoreCase(keyInfoInDB) != 0) {
                CMS.debug(method + " Key Info in the DB is NOT the same as the one from the token!");
                result = false;
            } else {
                CMS.debug(method + " Key Info in the DB IS the same as the one from the token!");
                result = true;
            }

        } else {
            result = true;
        }

        CMS.debug(method + " returning result: " + result);

        return result;

    }

    /* Only for debugging, extract bytes of a PK11SymKey
    private String getSymKeyData(PK11SymKey key) {
        String result = null;

        if(key == null) {
            result = "";
            return result;
        }

        try {
            byte [] extracted = key.getKeyData();

            TPSBuffer keyBuff = new TPSBuffer(extracted);

            result = keyBuff.toHexString();

        } catch (Exception e) {

            //Probably can not extract this key due to policy
            result = "";
        }

        return result;
    }
    */

    protected void auditAuth(String subjectID, String op,
            AppletInfo aInfo,
            String status,
            String authMgrId) {

        String auditType = "LOGGING_SIGNED_AUDIT_TOKEN_AUTH_FAILURE_9";
        if (status.equals("success"))
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_AUTH_SUCCESS_9";

        String auditMessage = CMS.getLogMessage(
                auditType,
                session.getIpAddress(),
                subjectID,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                (aInfo != null) ? aInfo.getMSNString() : null,
                status,
                op,
                getSelectedTokenType(),
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                authMgrId);
        audit(auditMessage);
    }

    /*
     * op can be can be "format", "enroll", or "pinReset"
     */
    protected void auditOpRequest(String op, AppletInfo aInfo,
            String status,
            String info) {
        String auditType = "LOGGING_SIGNED_AUDIT_TOKEN_OP_REQUEST_6";

        String auditMessage = CMS.getLogMessage(
                auditType,
                session.getIpAddress(),
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                (aInfo != null) ? aInfo.getMSNString() : null,
                status,
                op,
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                info);
        audit(auditMessage);
    }

    protected void auditFormat(String subjectID,
            AppletInfo aInfo,
            String status,
            String keyVersion,
            String info) {
        String auditType = "";
        switch (status) {
        case "success":
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_FORMAT_SUCCESS_9";
            break;
        default:
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_FORMAT_FAILURE_9";
        }

        String auditMessage = CMS.getLogMessage(
                auditType,
                session.getIpAddress(),
                subjectID,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                (aInfo != null) ? aInfo.getMSNString() : null,
                status,
                getSelectedTokenType(),
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                keyVersion,
                info);
        audit(auditMessage);
    }

    protected void auditAppletUpgrade(AppletInfo aInfo,
            String status,
            String keyVersion,
            String newVersion,
            String info) {

        String auditType = "";
        switch (status) {
        case "success":
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_APPLET_UPGRADE_SUCCESS_9";
            break;
        default:
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_APPLET_UPGRADE_FAILURE_9";
        }

        String auditMessage = CMS.getLogMessage(
                auditType,
                (session != null) ? session.getIpAddress() : null,
                userid,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                (aInfo != null) ? aInfo.getMSNString() : null,
                status,
                keyVersion,
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                newVersion,
                info);
        audit(auditMessage);
    }

    protected void auditKeyChangeoverRequired(AppletInfo aInfo,
            String oldKeyVersion,
            String newKeyVersion,
            String info) {

        String auditType = "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_REQUIRED_10";

        String auditMessage = CMS.getLogMessage(
                auditType,
                (session != null) ? session.getIpAddress() : null,
                userid,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                (aInfo != null) ? aInfo.getMSNString() : null,
                "na",
                getSelectedTokenType(),
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                oldKeyVersion,
                newKeyVersion,
                info);
        audit(auditMessage);
    }

    protected void auditKeyChangeover(AppletInfo aInfo,
            String status,
            String oldKeyVersion,
            String newKeyVersion,
            String info) {

        String auditType = "";
        switch (status) {
        case "success":
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_SUCCESS_10";
            break;
        default:
            auditType = "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_FAILURE_10";
        }

        String auditMessage = CMS.getLogMessage(
                auditType,
                (session != null) ? session.getIpAddress() : null,
                userid,
                (aInfo != null) ? aInfo.getCUIDhexStringPlain() : null,
                (aInfo != null) ? aInfo.getMSNString() : null,
                status,
                getSelectedTokenType(),
                (aInfo != null) ? aInfo.getFinalAppletVersion() : null,
                oldKeyVersion,
                newKeyVersion,
                info);
        audit(auditMessage);
    }

    /*
     * audit revoke, on-hold, or off-hold
     */
    protected void auditRevoke(String cuid,
            boolean isRevoke,
            int revokeReason,
            String status,
            String serial,
            String caConnId,
            String info) {

        String auditType = "LOGGING_SIGNED_AUDIT_TOKEN_CERT_STATUS_CHANGE_REQUEST_10";
        /*
         * requestType is "revoke", "on-hold", or "off-hold"
         */
        String requestType = "revoke";
        if (!isRevoke)
            requestType = "off-hold";
        else {
            if (revokeReason == RevocationReason.CERTIFICATE_HOLD.getCode()) {
                requestType = "on-hold";
            }
        }

        String auditMessage = CMS.getLogMessage(
                auditType,
                (session != null) ? session.getIpAddress() : null,
                userid,
                cuid,
                status,
                getSelectedTokenType(),
                serial,
                requestType,
                String.valueOf(revokeReason),
                caConnId,
                info);
        audit(auditMessage);
    }

    /**
     * Signed Audit Log
     *
     * This method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    public static void main(String[] args) {
    }

}
