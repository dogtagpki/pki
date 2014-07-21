package org.dogtagpki.server.tps.processor;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.zip.DataFormatException;

import netscape.security.provider.RSAPublicKey;
//import org.mozilla.jss.pkcs11.PK11ECPublicKey;
import netscape.security.util.BigInt;
import netscape.security.x509.X509CertImpl;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.authentication.TPSAuthenticator;
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.server.tps.channel.SecureChannel.TokenKeyType;
import org.dogtagpki.server.tps.cms.CAEnrollCertResponse;
import org.dogtagpki.server.tps.cms.CARemoteRequestHandler;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.main.ObjectSpec;
import org.dogtagpki.server.tps.main.PKCS11Obj;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU.SecurityLevel;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmsutil.util.Utils;

public class TPSEnrollProcessor extends TPSProcessor {

    public TPSEnrollProcessor(TPSSession session) {
        super(session);

    }

    @Override
    public void process(BeginOpMsg beginMsg) throws TPSException, IOException {
        if (beginMsg == null) {
            throw new TPSException("TPSEnrollrocessor.process: invalid input data, not beginMsg provided.",
                    TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        }
        setBeginMessage(beginMsg);
        setCurrentTokenOperation("enroll");
        checkIsExternalReg();

        enroll();

    }

    private void enroll() throws TPSException, IOException {
        CMS.debug("TPSEnrollProcessor enroll: entering...");
        TPSEngine engine = getTPSEngine();
        AppletInfo appletInfo = getAppletInfo();
        String resolverInstName = getResolverInstanceName();

        String tokenType = null;

        tokenType = resolveTokenProfile(resolverInstName, appletInfo.getCUIDString(), appletInfo.getMSNString(),
                appletInfo.getMajorVersion(), appletInfo.getMinorVersion());
        CMS.debug("TPSProcessor.enroll: calculated tokenType: " + tokenType);
        CMS.debug("TPSEnrollProcessor.enroll: tokenType: " + tokenType);

        checkProfileStateOK();

        if (engine.isTokenPresent(appletInfo.getCUIDString())) {
            //ToDo

        } else {
            checkAllowUnknownToken(TPSEngine.OP_FORMAT_PREFIX);
            checkAndAuthenticateUser(appletInfo, tokenType);
        }

        //ToDo: check transition state here

        boolean do_force_format = engine.raForceTokenFormat(appletInfo.getCUIDString());

        if (do_force_format) {
            CMS.debug("TPSEnrollProcessor.enroll: About to force format first due to policy.");
            //We will skip the auth step inside of format
            format(true);
        } else {
            checkAndUpgradeApplet(appletInfo);
            //Get new applet info
            appletInfo = getAppletInfo();
        }

        CMS.debug("TPSEnrollProcessor.enroll: Finished updating applet if needed.");

        //call stub for key changeover,will take more params when implemented.

        SecureChannel channel = checkAndUpgradeSymKeys();

        channel.externalAuthenticate();

        //Call stub to reset pin, method here will be small and call into common pin reset functionality.
        // Will be implemented during pin reset task.

        checkAndHandlePinReset(channel);

        String tksConnId = getTKSConnectorID();
        TPSBuffer plaintextChallenge = computeRandomData(16, tksConnId);

        //These will be used shortly
        TPSBuffer wrappedChallenge = encryptData(appletInfo, channel.getKeyInfoData(), plaintextChallenge, tksConnId);
        PKCS11Obj pkcs11objx = null;

        try {
            pkcs11objx = getCurrentObjectsOnToken(channel);
        } catch (DataFormatException e) {
            throw new TPSException("TPSEnrollProcessor.enroll: Failed to parse original token data: " + e.toString());
        }

        pkcs11objx.setCUID(appletInfo.getCUID());
        //ToDo: Add token to token db

        statusUpdate(10, "PROGRESS_PROCESS_PROFILE");

        EnrolledCertsInfo certsInfo = new EnrolledCertsInfo();
        certsInfo.setWrappedChallenge(wrappedChallenge);
        certsInfo.setPlaintextChallenge(plaintextChallenge);
        certsInfo.setPKCS11Obj(pkcs11objx);
        certsInfo.setStartProgress(15);
        certsInfo.setEndProgress(90);

        generateCertificates(certsInfo, channel, appletInfo);

        String tokenLabel = buildTokenLabel(certsInfo, appletInfo);

        pkcs11objx.setTokenName(new TPSBuffer(tokenLabel.getBytes()));

        int lastObjVer = pkcs11objx.getOldObjectVersion();

        CMS.debug("TPSEnrollProcessor.enroll: getOldObjectVersion: returning: " + lastObjVer);

        if (lastObjVer != 0) {
            while (lastObjVer == 0xff) {
                Random randomGenerator = new Random();
                lastObjVer = randomGenerator.nextInt(1000);
            }

            lastObjVer = lastObjVer + 1;
            CMS.debug("TPSEnrollProcessor.enroll: Setting objectVersion to: " + lastObjVer);
            pkcs11objx.setObjectVersion(lastObjVer);

        }

        pkcs11objx.setFormatVersion(pkcs11objx.getOldFormatVersion());

        // Make sure we have a good secure channel before writing out the final objects
        channel = setupSecureChannel();

        statusUpdate(92, "PROGRESS_WRITE_OBJECTS");

        writeFinalPKCS11ObjectToToken(pkcs11objx, appletInfo, channel);
        statusUpdate(98, "PROGRESS_ISSUER_INFO");
        writeIssuerInfoToToken(channel);

        statusUpdate(99, "PROGRESS_SET_LIFECYCLE");
        channel.setLifeycleState((byte) 0x0f);

        CMS.debug("TPSEnrollProcessor.enroll: leaving ...");

        statusUpdate(100, "PROGRESS_DONE_ENROLLMENT");
    }

    private void writeFinalPKCS11ObjectToToken(PKCS11Obj pkcs11objx, AppletInfo ainfo, SecureChannel channel)
            throws TPSException, IOException {
        if (pkcs11objx == null || ainfo == null || channel == null) {
            throw new TPSException("TPSErollProcessor.writeFinalPKCS11ObjectToToken: invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  entering...");

        IConfigStore configStore = CMS.getConfigStore();

        String compressConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + "pkcs11obj.compress.enable";

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  config to check: " + compressConfig);

        boolean doCompress = false;

        try {
            doCompress = configStore.getBoolean(compressConfig, true);
        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.writeFinalPKCS11ObjectToToken: internal error obtaining config value " + e);
        }

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  doCompress: " + doCompress);

        TPSBuffer tokenData = null;

        if (doCompress) {
            tokenData = pkcs11objx.getCompressedData();

        } else {
            tokenData = pkcs11objx.getData();
        }

        if (tokenData.size() > ainfo.getTotalMem()) {

            throw new TPSException(
                    "TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  NOt enough memory to write certificates!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        byte[] zobjectid = { (byte) 'z', (byte) '0', 0, 0 };
        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };
        TPSBuffer zobjidBuf = new TPSBuffer(zobjectid);

        channel.createObject(zobjidBuf, new TPSBuffer(perms), tokenData.size());

        channel.writeObject(zobjidBuf, tokenData);

        CMS.debug("TPSEnrollProcessor.writeFinalPKCS11ObjectToToken:  leaving successfully ...");

    }

    private void checkAndAuthenticateUser(AppletInfo appletInfo, String tokenType) throws TPSException {
        IAuthCredentials userCred;
        IAuthToken authToken;
        if (!isExternalReg) {
            // authenticate per profile/tokenType configuration
            String configName = TPSEngine.OP_ENROLL_PREFIX + "." + tokenType + ".auth.enable";
            IConfigStore configStore = CMS.getConfigStore();
            boolean isAuthRequired;
            try {
                CMS.debug("TPSEnrollProcessor.checkAndAuthenticateUser: getting config: " + configName);
                isAuthRequired = configStore.getBoolean(configName, true);
            } catch (EBaseException e) {
                CMS.debug("TPSEnrollProcessor.checkAndAuthenticateUser: Internal Error obtaining mandatory config values. Error: "
                        + e);
                throw new TPSException("TPS error getting config values from config store.",
                        TPSStatus.STATUS_ERROR_MISCONFIGURATION);
            }
            if (isAuthRequired) {
                try {
                    TPSAuthenticator userAuth =
                            getAuthentication(TPSEngine.OP_ENROLL_PREFIX, tokenType);
                    userCred = requestUserId(TPSEngine.ENROLL_OP, appletInfo.getCUIDString(), userAuth,
                            beginMsg.getExtensions());
                    authToken = authenticateUser(TPSEngine.ENROLL_OP, userAuth, userCred);
                    CMS.debug("TPSEnrollProcessor.checkAndAuthenticateUser: auth passed: userid: "
                            + authToken.get("userid"));
                    userid = authToken.getInString("userid");
                } catch (Exception e) {
                    // all exceptions are considered login failure
                    CMS.debug("TPSEnrollProcessor.checkAndAuthenticateUser:: authentication exception thrown: " + e);
                    throw new TPSException("TPS error user authentication failed.",
                            TPSStatus.STATUS_ERROR_LOGIN);
                }
            } else {
                throw new TPSException(
                        "TPSEnrollProcessor.checkAndAuthenticateUser: TPS enrollment must have authentication enabled.",
                        TPSStatus.STATUS_ERROR_LOGIN);

            }

        }
    }

    private void checkAndHandlePinReset(SecureChannel channel) throws TPSException, IOException {

        CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset entering...");

        if (channel == null) {
            throw new TPSException("TPSProcessor.checkAndHandlePinReset: invalid input data!",
                    TPSStatus.STATUS_ERROR_TOKEN_RESET_PIN_FAILED);
        }

        IConfigStore configStore = CMS.getConfigStore();

        String pinResetEnableConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_ENABLE;

        CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset config to check: " + pinResetEnableConfig);

        String minLenConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_MIN_LEN;

        CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset config to check: " + minLenConfig);

        String maxLenConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_MAX_LEN;

        CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset config to check: " + maxLenConfig);

        String maxRetriesConfig = "op." + currentTokenOperation + "." + selectedTokenType + "."
                + TPSEngine.CFG_PIN_RESET_MAX_RETRIES;

        CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset config to check: " + maxRetriesConfig);

        String pinStringConfig = TPSEngine.CFG_PIN_RESET_STRING;

        CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset config to check: " + pinStringConfig);

        boolean enabled = false;
        int minLen;
        int maxLen;
        int maxRetries;
        String stringName;

        try {

            enabled = configStore.getBoolean(pinResetEnableConfig, true);

            if (enabled == false) {
                CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset:  Pin Reset not allowed by configuration, exiting...");
                return;

            }

            minLen = configStore.getInteger(minLenConfig, 4);
            maxLen = configStore.getInteger(maxLenConfig, 10);
            maxRetries = configStore.getInteger(maxRetriesConfig, 0x7f);
            stringName = configStore.getString(pinStringConfig, "password");

            CMS.debug("TPSEnrollProcessor.checkAndHandlePinReset: config vals: enabled: " + enabled + " minLen: "
                    + minLen + " maxLen: " + maxLen);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.checkAndHandlePinReset: internal error in getting value from config.");
        }

        String new_pin = requestNewPin(minLen, maxLen);

        channel.createPin(0x0, maxRetries, stringName);

        channel.resetPin(0x0, new_pin);

    }

    private void checkAndUpgradeApplet(AppletInfo appletInfo) throws TPSException, IOException {
        // TODO Auto-generated method stub

        CMS.debug("checkAndUpgradeApplet: entering..");

        SecurityLevel securityLevel = SecurityLevel.SECURE_MSG_MAC;

        boolean useEncryption = checkUpdateAppletEncryption();

        String tksConnId = getTKSConnectorID();
        if (useEncryption)
            securityLevel = SecurityLevel.SECURE_MSG_MAC_ENC;

        if (checkForAppletUpdateEnabled()) {
            String targetAppletVersion = checkForAppletUpgrade(currentTokenOperation);
            upgradeApplet(currentTokenOperation, targetAppletVersion, securityLevel, getBeginMessage().getExtensions(),
                    tksConnId, 5, 12);
        }

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

    private PKCS11Obj getCurrentObjectsOnToken(SecureChannel channel) throws TPSException, IOException,
            DataFormatException {

        byte seq = 0;

        TPSBuffer objects = null;

        int lastFormatVersion = 0x0100;
        int lastObjectVersion;
        Random randomGenerator = new Random();

        lastObjectVersion = randomGenerator.nextInt(1000);

        CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: Random lastObjectVersion: " + lastObjectVersion);

        PKCS11Obj pkcs11objx = new PKCS11Obj();
        pkcs11objx.setOldFormatVersion(lastFormatVersion);
        pkcs11objx.setOldObjectVersion(lastObjectVersion);

        do {

            objects = listObjects(seq);

            if (objects != null) {
                CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: objects: " + objects.toHexString());
            }

            if (objects == null) {
                pkcs11objx.setOldObjectVersion(lastObjectVersion);
                seq = 0;
            } else {
                seq = 1; // get next entry

                TPSBuffer objectID = objects.substr(0, 4);
                TPSBuffer objectLen = objects.substr(4, 4);

                long objectIDVal = objectID.getLongFrom4Bytes(0);

                long objectLenVal = objectLen.getLongFrom4Bytes(0);

                TPSBuffer obj = channel.readObject(objectID, 0, (int) objectLenVal);

                if (obj != null) {
                    CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: obj: " + obj.toHexString());
                }

                if ((char) objectID.at(0) == (byte) 'z' && objectID.at(1) == (byte) '0') {
                    lastFormatVersion = obj.getIntFrom2Bytes(0);
                    lastObjectVersion = obj.getIntFrom2Bytes(2);

                    CMS.debug("PKCS11Obj.getCurrentObjectsOnToken: Versions read from token:  lastFormatVersion : "
                            + lastFormatVersion
                            + " lastObjectVersion: " + lastObjectVersion);

                    pkcs11objx = PKCS11Obj.parse(obj, 0);

                    pkcs11objx.setOldFormatVersion(lastFormatVersion);
                    pkcs11objx.setOldObjectVersion(lastObjectVersion);
                    seq = 0;

                } else {
                    ObjectSpec objSpec = ObjectSpec.parseFromTokenData(objectIDVal, obj);
                    pkcs11objx.addObjectSpec(objSpec);
                }

                CMS.debug("TPSEnrollProcessor.getCurrentObjectsOnToken. just read object from token: "
                        + obj.toHexString());
            }

        } while (seq != 0);

        return pkcs11objx;
    }

    //Stub to generate a certificate, more to come
    private void generateCertificates(EnrolledCertsInfo certsInfo, SecureChannel channel, AppletInfo aInfo)
            throws TPSException, IOException {

        CMS.debug("TPSProcess.generateCertificates: begins ");
        if (certsInfo == null || aInfo == null) {
            throw new TPSException("TPSEnrollProcessor.generateCertificates: Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        int keyTypeNum = getNumberCertsToEnroll();

        certsInfo.setNumCertsToEnroll(keyTypeNum);

        CMS.debug("TPSEnrollProcessor.generateCertificate: Number of certs to enroll: " + keyTypeNum);

        for (int i = 0; i < keyTypeNum; i++) {
            String keyType = getConfiguredKeyType(i);
            certsInfo.setCurrentCertIndex(i);
            generateCertificate(certsInfo, channel, aInfo, keyType);
            channel = setupSecureChannel();
        }

        CMS.debug("TPSProcess.generateCertificates: ends ");
    }

    private String buildTokenLabel(EnrolledCertsInfo certsInfo, AppletInfo ainfo) throws TPSException {
        String label = null;

        if (certsInfo == null || ainfo == null) {
            throw new TPSException("TPSEnrollProcessor.buildTokenLabel: invalide input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSEnrollProcessor.buildTokenLabel: entering...");

        IConfigStore configStore = CMS.getConfigStore();

        String configName = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType() + ".keyGen.tokenName";
        String pattern = null;

        try {
            pattern = configStore.getString(configName, "$cuid$");
        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.buildTokenLabel: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        CMS.debug("TPSEnrollProcessor.buildTokenLabel: pattern: " + pattern);

        Map<String, String> nv = new LinkedHashMap<String, String>();

        nv.put("cuid", ainfo.getCUIDString());
        nv.put("msn", ainfo.getMSNString());
        nv.put("userid", userid);
        nv.put("auth.cn", userid);
        nv.put("profileId", getSelectedTokenType());

        label = mapPattern((LinkedHashMap<String, String>) nv, pattern);

        CMS.debug("TPSEnrollProcessor.buildTokenLabel: returning: " + label);

        return label;

    }

    private void generateCertificate(EnrolledCertsInfo certsInfo, SecureChannel channel, AppletInfo aInfo,
            String keyType) throws TPSException, IOException {

        CMS.debug("TPSEnrollProcessor.generateCertificate: entering ...");

        if (certsInfo == null || aInfo == null) {
            throw new TPSException("TPSEnrollProcessor.generateCertificate: Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //get the params needed all at once

        IConfigStore configStore = CMS.getConfigStore();
        CertEnrollInfo cEnrollInfo = new CertEnrollInfo();

        try {

            String keyTypePrefix = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType() + ".keyGen." + keyType;
            CMS.debug("TPSEnrollProcessor.generateCertificate: keyTypePrefix: " + keyTypePrefix);

            String configName = keyTypePrefix + ".ca.profileId";
            String profileId = configStore.getString(configName);
            CMS.debug("TPSEnrollProcessor.generateCertificate: profileId: " + profileId);

            configName = keyTypePrefix + ".certId";
            String certId = configStore.getString(configName, "C0");
            CMS.debug("TPSEnrollProcessor.generateCertificate: certId: " + certId);

            configName = keyTypePrefix + ".certAttrId";
            String certAttrId = configStore.getString(configName, "c0");
            CMS.debug("TPSEnrollProcessor.generateCertificate: certAttrId: " + certAttrId);

            configName = keyTypePrefix + ".privateKeyAttrId";
            String priKeyAttrId = configStore.getString(configName, "k0");
            CMS.debug("TPSEnrollProcessor.generateCertificate: priKeyAttrId: " + priKeyAttrId);

            configName = keyTypePrefix + ".publicKeyAttrId";
            String publicKeyAttrId = configStore.getString(configName, "k1");
            CMS.debug("TPSEnrollProcessor.generateCertificate: publicKeyAttrId: " + publicKeyAttrId);

            configName = keyTypePrefix + ".keySize";
            int keySize = configStore.getInteger(configName, 1024);
            CMS.debug("TPSEnrollProcessor.generateCertificate: keySize: " + keySize);

            //Default RSA_CRT=2
            configName = keyTypePrefix + ".alg";
            int algorithm = configStore.getInteger(configName, 2);
            CMS.debug("TPSEnrollProcessor.generateCertificate: algorithm: " + algorithm);

            configName = keyTypePrefix + ".publisherId";
            String publisherId = configStore.getString(configName, "");
            CMS.debug("TPSEnrollProcessor.generateCertificate: publisherId: " + publisherId);

            configName = keyTypePrefix + ".keyUsage";
            int keyUsage = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: keyUsage: " + keyUsage);

            configName = keyTypePrefix + ".keyUser";
            int keyUser = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: keyUser: " + keyUser);

            configName = keyTypePrefix + ".privateKeyNumber";
            int priKeyNumber = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: privateKeyNumber: " + priKeyNumber);

            configName = keyTypePrefix + ".publicKeyNumber";
            int pubKeyNumber = configStore.getInteger(configName, 0);
            CMS.debug("TPSEnrollProcessor.generateCertificate: pubKeyNumber: " + pubKeyNumber);

            // get key capabilites to determine if the key type is SIGNING,
            // ENCRYPTION, or SIGNING_AND_ENCRYPTION

            configName = keyTypePrefix + ".private.keyCapabilities.sign";
            boolean isSigning = configStore.getBoolean(configName);
            CMS.debug("TPSEnrollProcessor.generateCertificate: isSigning: " + isSigning);

            configName = keyTypePrefix + ".public.keyCapabilities.encrypt";
            CMS.debug("TPSEnrollProcessor.generateCertificate: encrypt config name: " + configName);
            boolean isEncrypt = configStore.getBoolean(configName);
            CMS.debug("TPSEnrollProcessor.generateCertificate: isEncrypt: " + isEncrypt);

            TokenKeyType keyTypeEnum;

            if (isSigning && isEncrypt) {
                keyTypeEnum = TokenKeyType.KEY_TYPE_SIGNING_AND_ENCRYPTION;
            } else if (isSigning) {
                keyTypeEnum = TokenKeyType.KEY_TYPE_SIGNING;
            } else if (isEncrypt) {
                keyTypeEnum = TokenKeyType.KEY_TYPE_ENCRYPTION;
            } else {
                CMS.debug("TPSEnrollProcessor.generateCertificate: Illegal toke key type!");
                throw new TPSException("TPSEnrollProcessor.generateCertificate: Illegal toke key type!",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

            CMS.debug("TPSEnrollProcessor.generateCertificate: keyTypeEnum value: " + keyTypeEnum);

            cEnrollInfo.setKeyTypeEnum(keyTypeEnum);
            cEnrollInfo.setProfileId(profileId);
            cEnrollInfo.setCertId(certId);
            cEnrollInfo.setCertAttrId(certAttrId);
            cEnrollInfo.setPrivateKeyAttrId(priKeyAttrId);
            cEnrollInfo.setPublicKeyAttrId(publicKeyAttrId);
            cEnrollInfo.setKeySize(keySize);
            cEnrollInfo.setAlgorithm(algorithm);
            cEnrollInfo.setPublisherId(publisherId);
            cEnrollInfo.setKeyUsage(keyUsage);
            cEnrollInfo.setKeyUser(keyUser);
            cEnrollInfo.setPrivateKeyNumber(priKeyNumber);
            cEnrollInfo.setPublicKeyNumber(pubKeyNumber);
            cEnrollInfo.setKeyType(keyType);
            cEnrollInfo.setKeyTypePrefix(keyTypePrefix);

            int certsStartProgress = certsInfo.getStartProgressValue();
            int certsEndProgress = certsInfo.getEndProgressValue();
            int currentCertIndex = certsInfo.getCurrentCertIndex();
            int totalNumCerts = certsInfo.getNumCertsToEnroll();

            int progressBlock = (certsEndProgress - certsStartProgress) / totalNumCerts;

            int startCertProgValue = certsStartProgress + currentCertIndex * progressBlock;

            int endCertProgValue = startCertProgValue + progressBlock;

            cEnrollInfo.setStartProgressValue(startCertProgValue);
            cEnrollInfo.setEndProgressValue(endCertProgValue);

        } catch (EBaseException e) {

            throw new TPSException(
                    "TPSEnrollProcessor.generateCertificate: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        enrollOneCertificate(certsInfo, cEnrollInfo, aInfo, channel);

    }

    private void enrollOneCertificate(EnrolledCertsInfo certsInfo, CertEnrollInfo cEnrollInfo, AppletInfo aInfo,
            SecureChannel channel) throws TPSException, IOException {

        CMS.debug("TPSEnrollProcessor.enrollOneCertificate: entering ...");

        if (certsInfo == null || aInfo == null || cEnrollInfo == null) {
            throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: Bad Input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        statusUpdate(cEnrollInfo.getStartProgressValue(), "PROGRESS_KEY_GENERATION");
        boolean serverSideKeyGen = checkForServerSideKeyGen(cEnrollInfo);
        boolean objectOverwrite = checkForObjectOverwrite(cEnrollInfo);

        PKCS11Obj pkcs11obj = certsInfo.getPKCS11Obj();

        int keyAlg = cEnrollInfo.getAlgorithm();

        boolean isECC = getTPSEngine().isAlgorithmECC(keyAlg);

        if (objectOverwrite) {
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: We are configured to overwrite existing cert objects.");

        } else {

            boolean certIdExists = pkcs11obj.doesCertIdExist(cEnrollInfo.getCertId());

            //Bomb out if cert exists, we ca't overwrite

            if (certIdExists) {
                throw new TPSException(
                        "TPSEnrollProcessor.enrollOneCertificate: Overwrite of certificates not allowed!",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        }

        if (serverSideKeyGen) {
            //Handle server side keyGen

        } else {
            //Handle token side keyGen
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate: about to generate the keys on the token.");

            int algorithm = 0x80;

            if (certsInfo.getKeyCheck() != null) {
                algorithm = 0x81;
            }

            if (isECC) {
                algorithm = keyAlg;
            }

            int pe1 = (cEnrollInfo.getKeyUser() << 4) + cEnrollInfo.getPrivateKeyNumber();
            int pe2 = (cEnrollInfo.getKeyUsage() << 4) + cEnrollInfo.getPublicKeyNumber();

            int size = channel.startEnrollment(pe1, pe2, certsInfo.getWrappedChallenge(), certsInfo.getKeyCheck(),
                    algorithm, cEnrollInfo.getKeySize(), 0x0);

            byte[] iobytes = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
            TPSBuffer iobuf = new TPSBuffer(iobytes);

            TPSBuffer public_key_blob = channel.readObject(iobuf, 0, size);

            PublicKey parsedPubKey = parsePublicKeyBlob(public_key_blob, isECC);
            byte[] parsedPubKey_ba = parsedPubKey.getEncoded();

            // enrollment begins
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: enrollment begins");
            try {
                String caConnID = getCAConnectorID();
                CARemoteRequestHandler caRH = new CARemoteRequestHandler(caConnID);
                TPSBuffer encodedParsedPubKey = new TPSBuffer(parsedPubKey_ba);
                AppletInfo appletInfo = getAppletInfo();
                selectCoolKeyApplet();
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: userid =" + userid + ", cuid="
                        + appletInfo.getCUIDString());
                CAEnrollCertResponse caEnrollResp = caRH.enrollCertificate(encodedParsedPubKey, userid,
                        appletInfo.getCUIDString(), getSelectedTokenType(),
                        cEnrollInfo.getKeyType());
                String retCertB64 = caEnrollResp.getCertB64();

                CMS.debug("TPSEnrollProcessor.enrollOneCertificate: retCertB64: " + retCertB64);

                byte[] cert_bytes = Utils.base64decode(retCertB64);

                TPSBuffer cert_bytes_buf = new TPSBuffer(cert_bytes);
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate: retCertB64: " + cert_bytes_buf.toHexString());

                if (retCertB64 != null)
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert b64 =" + retCertB64);
                else {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert b64 not found");
                    throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: new cert b64 not found",
                            TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                }
                X509CertImpl x509Cert = caEnrollResp.getCert();
                if (x509Cert != null)
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert retrieved");
                else {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: new cert not found");
                    throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: new cert not found",
                            TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                }

                certsInfo.addCertificate(x509Cert);
                certsInfo.addKType(cEnrollInfo.getKeyType());
                certsInfo.addOrigin(aInfo.getCUIDString());

                SubjectPublicKeyInfo publicKeyInfo = null;
                try {
                    publicKeyInfo = new SubjectPublicKeyInfo(parsedPubKey);
                } catch (InvalidBERException e) {
                    CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: cant get publicKeyInfo object.");
                    throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: can't get publcKeyInfo object.",
                            TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
                }

                //Create label ToDo: Do this the correct way later

                String label = buildCertificateLabel(cEnrollInfo, aInfo);
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: cert label: " + label);

                TPSBuffer keyid = new TPSBuffer(makeKeyIDFromPublicKeyInfo(publicKeyInfo.getEncoded()));

                RSAPublicKey rsaPubKey = (RSAPublicKey) parsedPubKey;
                TPSBuffer modulus = new TPSBuffer(rsaPubKey.getModulus().toByteArray());
                TPSBuffer exponent = new TPSBuffer(rsaPubKey.getPublicExponent().toByteArray());

                //Write cert to the token

                long l1, l2;
                long objid;
                PKCS11Obj pkcs11Obj = certsInfo.getPKCS11Obj();

                String certId = cEnrollInfo.getCertId();

                l1 = (certId.charAt(0) & 0xff) << 24;
                l2 = (certId.charAt(1) & 0xff) << 16;
                objid = l1 + l2;

                CMS.debug("TPSEnrollProcess.enrollOneCertificate:  cert objid long: " + objid);

                ObjectSpec certObjSpec = ObjectSpec.parseFromTokenData(objid, new TPSBuffer(cert_bytes));
                pkcs11Obj.addObjectSpec(certObjSpec);

                String certAttrId = cEnrollInfo.getCertAttrId();

                TPSBuffer certAttrsBuffer = channel.createPKCS11CertAttrsBuffer(cEnrollInfo.getKeyTypeEnum(),
                        certAttrId, label, keyid);

                l1 = (certAttrId.charAt(0) & 0xff) << 24;
                l2 = (certAttrId.charAt(1) & 0xff) << 16;
                objid = l1 + l2;

                CMS.debug("TPSEnrollProcess.enrollOneCertificate:  cert attr objid long: " + objid);
                ObjectSpec certAttrObjSpec = ObjectSpec.parseFromTokenData(objid, certAttrsBuffer);
                pkcs11Obj.addObjectSpec(certAttrObjSpec);

                //Add the pri key attrs object

                String priKeyAttrId = cEnrollInfo.getPrivateKeyAttrId();

                l1 = (priKeyAttrId.charAt(0) & 0xff) << 24;
                l2 = (priKeyAttrId.charAt(1) & 0xff) << 16;

                objid = l1 + l2;

                CMS.debug("TPSEnrollProcess.enrollOneCertificate: pri key objid long: " + objid);

                TPSBuffer privKeyAttrsBuffer = channel.createPKCS11PriKeyAttrsBuffer(priKeyAttrId, label, keyid,
                        modulus, cEnrollInfo.getKeyTypePrefix());

                ObjectSpec priKeyObjSpec = ObjectSpec.parseFromTokenData(objid, privKeyAttrsBuffer);
                pkcs11obj.addObjectSpec(priKeyObjSpec);

                // Now add the public key object

                String pubKeyAttrId = cEnrollInfo.getPublicKeyAttrId();

                l1 = (pubKeyAttrId.charAt(0) & 0xff) << 24;
                l2 = (pubKeyAttrId.charAt(1) & 0xff) << 16;

                objid = l1 + l2;
                CMS.debug("TPSEnrollProcess.enrollOneCertificate: pub key objid long: " + objid);

                TPSBuffer pubKeyAttrsBuffer = channel.createPKCS11PublicKeyAttrsBuffer(pubKeyAttrId, label, keyid,
                        modulus, exponent, cEnrollInfo.getKeyTypePrefix());
                ObjectSpec pubKeyObjSpec = ObjectSpec.parseFromTokenData(objid, pubKeyAttrsBuffer);
                pkcs11obj.addObjectSpec(pubKeyObjSpec);

            } catch (EBaseException e) {
                CMS.debug("TPSEnrollProcessor.enrollOneCertificate::" + e);
                throw new TPSException("TPSEnrollProcessor.enrollOneCertificate: Exception thrown: " + e,
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
            CMS.debug("TPSEnrollProcessor.enrollOneCertificate:: enrollment ends");

        }

        statusUpdate(cEnrollInfo.getEndProgressValue(), "PROGRESS_ENROLL_CERT");
        CMS.debug("TPSEnrollProcessor.enrollOneCertificate ends");

    }

    private String buildCertificateLabel(CertEnrollInfo cEnrollInfo, AppletInfo ainfo) throws TPSException {

        CMS.debug("TPSEnrollProcessor.buildCertificateLabel");

        if (cEnrollInfo == null) {
            throw new TPSException("TPSErollProcessor.buildCertificateLabel: Invalid input params!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        String label = null;
        String pattern = null;

        String defaultLabel = cEnrollInfo.getKeyType() + " key for $userid$";

        IConfigStore configStore = CMS.getConfigStore();

        String configValue = "op." + currentTokenOperation + "." + selectedTokenType + ".keyGen."
                + cEnrollInfo.getKeyType() + ".label";

        CMS.debug("TPSEnrollProcessor.buildCertificateLabel: label config: " + configValue);

        try {
            pattern = configStore.getString(
                    configValue, defaultLabel);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.buildCertificateLabel: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        Map<String, String> nv = new LinkedHashMap<String, String>();

        nv.put("cuid", ainfo.getCUIDString());
        nv.put("msn", ainfo.getMSNString());
        nv.put("userid", userid);
        nv.put("auth.cn", userid);
        nv.put("profileId", getSelectedTokenType());

        label = mapPattern((LinkedHashMap<String, String>) nv, pattern);

        CMS.debug("TPSEnrollProcessor.buildCertificateLabel: returning: " + label);

        return label;
    }

    /**
     * Extracts information from the public key blob and verify proof.
     *
     * Muscle Key Blob Format (RSA Public Key)
     * ---------------------------------------
     *
     * The key generation operation places the newly generated key into
     * the output buffer encoding in the standard Muscle key blob format.
     * For an RSA key the data is as follows:
     *
     * Byte Encoding (0 for plaintext)
     *
     * Byte Key Type (1 for RSA public)
     *
     * Short Key Length (1024 û high byte first)
     *
     * Short Modulus Length
     *
     * Byte[] Modulus
     *
     * Short Exponent Length
     *
     * Byte[] Exponent
     *
     *
     * ECC KeyBlob Format (ECC Public Key)
     * ----------------------------------
     *
     * Byte Encoding (0 for plaintext)
     *
     * Byte Key Type (10 for ECC public)
     *
     * Short Key Length (256, 384, 521 high byte first)
     *
     * Byte[] Key (W)
     *
     *
     * Signature Format (Proof)
     * ---------------------------------------
     *
     * The key generation operation creates a proof-of-location for the
     * newly generated key. This proof is a signature computed with the
     * new private key using the RSA-with-MD5 signature algorithm. The
     * signature is computed over the Muscle Key Blob representation of
     * the new public key and the challenge sent in the key generation
     * request. These two data fields are concatenated together to form
     * the input to the signature, without any other data or length fields.
     *
     * Byte[] Key Blob Data
     *
     * Byte[] Challenge
     *
     *
     * Key Generation Result
     * ---------------------------------------
     *
     * The key generation command puts the key blob and the signature (proof)
     * into the output buffer using the following format:
     *
     * Short Length of the Key Blob
     *
     * Byte[] Key Blob Data
     *
     * Short Length of the Proof
     *
     * Byte[] Proof (Signature) Data
     *
     * @param blob the publickey blob to be parsed
     * @param challenge the challenge generated by TPS
     *
     ******/
    private PublicKey parsePublicKeyBlob(
            TPSBuffer public_key_blob,
            /* TPSBuffer challenge,*/
            boolean isECC)
            throws TPSException {
        PublicKey parsedPubKey = null;

        if (public_key_blob == null /*|| challenge == null*/) {
            throw new TPSException(
                    "TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! Missing public_key_blob or challenge",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: public key blob from token to parse: "
                + public_key_blob.toHexString());
        /*
         * decode blob into structures
         */

        // offset to the beginning of the public key length.  should be 0
        int pkeyb_len_offset = 0;

        /*
         * now, convert lengths
         */
        // 1st, keyblob length
        /*
                byte len0 = public_key_blob.at(pkeyb_len_offset);
                byte len1 = public_key_blob.at(pkeyb_len_offset + 1);
                int pkeyb_len = (len0 << 8) | (len1 & 0xFF);
        */
        int pkeyb_len = public_key_blob.getIntFrom2Bytes(pkeyb_len_offset);
        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: pkeyb_len = " +
                pkeyb_len + ", isECC: " + isECC);
        // public key blob
        TPSBuffer pkeyb = public_key_blob.substr(pkeyb_len_offset + 2, pkeyb_len);
        if (pkeyb == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: pkeyb null ");
            throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! pkeyb null",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: pkeyb = "
                + pkeyb.toHexString());

        //  2nd, proof blob length
        int proofb_len_offset = pkeyb_len_offset + 2 + pkeyb_len;
        /*
                len0 = public_key_blob.at(proofb_len_offset);
                len1 = public_key_blob.at(proofb_len_offset + 1);
                int proofb_len = (len0 << 8 | len1 & 0xFF);
        */
        int proofb_len = public_key_blob.getIntFrom2Bytes(proofb_len_offset);
        // proof blob
        TPSBuffer proofb = public_key_blob.substr(proofb_len_offset + 2, proofb_len);
        if (proofb == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: proofb null ");
            throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! proofb null",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: proofb = "
                + proofb.toHexString());

        // convert pkeyb to pkey
        // 1 byte encoding, 1 byte key type, 2 bytes key length, then the key
        int pkey_offset = 4;
        /*
                len0 = pkeyb.at(pkey_offset);
                len1 = pkeyb.at(pkey_offset + 1);
        */
        if (!isECC) {
            //            int mod_len = len0 << 8 | len1 & 0xFF;
            int mod_len = pkeyb.getIntFrom2Bytes(pkey_offset);
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: mod_len= " + mod_len);
            /*
                        len0 = pkeyb.at(pkey_offset + 2 + mod_len);
                        len1 = pkeyb.at(pkey_offset + 2 + mod_len + 1);
                        int exp_len = len0 << 8 | len1 & 0xFF;
            */
            int exp_len = pkeyb.getIntFrom2Bytes(pkey_offset + 2 + mod_len);
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: exp_len= " + exp_len);

            TPSBuffer modb = pkeyb.substr(pkey_offset + 2, mod_len);
            if (modb == null) {
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: modb null ");
                throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! modb null",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: modb= "
                    + modb.toHexString());
            TPSBuffer expb = pkeyb.substr(pkey_offset + 2 + mod_len + 2, exp_len);

            if (expb == null) {
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: expb null ");
                throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data! expb null",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: expb= "
                    + expb.toHexString());
            BigInt modb_bi = new BigInt(modb.toBytesArray());
            BigInt expb_bi = new BigInt(expb.toBytesArray());
            try {
                RSAPublicKey rsa_pub_key = new RSAPublicKey(modb_bi, expb_bi);
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: public key blob converted to RSAPublicKey");
                if (rsa_pub_key != null) {
                    parsedPubKey = rsa_pub_key;
                }
            } catch (InvalidKeyException e) {
                CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob:InvalidKeyException thrown");
                throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Exception thrown: " + e,
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }
        } else {
            // TODO: handle ECC
        }

        // TODO: challenge verification

        // sanity-check parsedPubKey before return
        if (parsedPubKey == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey null");
            throw new TPSException(
                    "TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey null.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        } else {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey not null");
        }
        byte[] parsedPubKey_ba = parsedPubKey.getEncoded();
        if (parsedPubKey_ba == null) {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey_ba null");
            throw new TPSException(
                    "TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey encoding failure.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        } else {
            CMS.debug("TPSEnrollProcessor.parsePublicKeyBlob: parsedPubKey getEncoded not null");
        }

        return parsedPubKey;
    }

    private boolean checkForServerSideKeyGen(CertEnrollInfo cInfo) throws TPSException {

        if (cInfo == null) {
            throw new TPSException("TPSEnrollProcessor.checkForServerSideKeyGen: invalid cert info.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        IConfigStore configStore = CMS.getConfigStore();
        boolean serverSideKeygen = false;

        try {
            String configValue = cInfo.getKeyTypePrefix() + "." + TPSEngine.CFG_SERVER_KEYGEN_ENABLE;
            CMS.debug("TPSEnrollProcessor.checkForServerSideKeyGen: config: " + configValue);
            serverSideKeygen = configStore.getBoolean(
                    configValue, false);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.checkForServerSideKeyGen: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.checkForServerSideKeyGen: returning: " + serverSideKeygen);

        return serverSideKeygen;

    }

    private boolean checkForObjectOverwrite(CertEnrollInfo cInfo) throws TPSException {

        if (cInfo == null) {
            throw new TPSException("TPSEnrollProcessor.checkForObjectOverwrite: invalid cert info.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }
        IConfigStore configStore = CMS.getConfigStore();
        boolean objectOverwrite = false;

        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + getSelectedTokenType() + ".keyGen."
                    + cInfo.getKeyType() + "." + TPSEngine.CFG_OVERWRITE;

            CMS.debug("TPSProcess.checkForObjectOverwrite: config: " + configValue);
            objectOverwrite = configStore.getBoolean(
                    configValue, true);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.checkForServerSideKeyGen: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.checkForObjectOverwrite: returning: " + objectOverwrite);

        return objectOverwrite;

    }

    private String getConfiguredKeyType(int keyTypeIndex) throws TPSException {

        IConfigStore configStore = CMS.getConfigStore();
        String keyType = null;

        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_KEYGEN_KEYTYPE_VALUE + "." + keyTypeIndex;
            keyType = configStore.getString(
                    configValue, null);

        } catch (EBaseException e) {
            throw new TPSException(
                    "TPSEnrollProcessor.getConfiguredKeyType: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //We would really like one of these to exist

        if (keyType == null) {
            throw new TPSException(
                    "TPSEnrollProcessor.getConfiguredKeyType: Internal error finding config value: ",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSProcess.getConfiguredKeyType: returning: " + keyType);

        return keyType;

    }

    protected int getNumberCertsToEnroll() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        int keyTypeNum = 0;
        try {
            String configValue = TPSEngine.OP_ENROLL_PREFIX + "." + selectedTokenType + "."
                    + TPSEngine.CFG_KEYGEN_KEYTYPE_NUM;
            keyTypeNum = configStore.getInteger(
                    configValue, 0);

        } catch (EBaseException e) {
            throw new TPSException("TPSEnrollProcessor.getNumberCertsToEnroll: Internal error finding config value: "
                    + e,
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        if (keyTypeNum == 0) {
            throw new TPSException(
                    "TPSEnrollProcessor.getNumberCertsToEnroll: invalid number of certificates configured!",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }
        CMS.debug("TPSProcess.getNumberCertsToEnroll: returning: " + keyTypeNum);

        return keyTypeNum;
    }

    protected String getCAConnectorID() throws TPSException {
        IConfigStore configStore = CMS.getConfigStore();
        String id = null;

        String config = "op." + currentTokenOperation + "." + selectedTokenType + ".ca.conn";

        try {
            id = configStore.getString(config, "ca1");
        } catch (EBaseException e) {
            throw new TPSException("TPSEnrollProcessor.getCAConnectorID: Internal error finding config value.");

        }

        CMS.debug("TPSEnrollProcessor.getCAConectorID: returning: " + id);

        return id;
    }

    private TPSBuffer makeKeyIDFromPublicKeyInfo(byte[] publicKeyInfo) throws TPSException {

        final String alg = "SHA1";

        if (publicKeyInfo == null) {
            throw new TPSException("TPSEnrollProcessor.makeKeyFromPublicKeyInfo: invalid input data",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSBuffer keyID = null;

        byte[] mozillaDigestOut;

        java.security.MessageDigest mozillaDigest;
        try {
            mozillaDigest = java.security.MessageDigest.getInstance(alg);
        } catch (NoSuchAlgorithmException e) {
            throw new TPSException("TPSEnrollProcessor.makeKeyFromPublicKeyInfo: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        mozillaDigestOut = mozillaDigest.digest(publicKeyInfo);

        if (mozillaDigestOut.length == mozillaDigest.getDigestLength()) {
            System.out.println(mozillaDigest.getAlgorithm() + " " +
                    " digest output size is " + mozillaDigestOut.length);
        } else {
            throw new TPSException("ERROR: digest output size is " +
                    mozillaDigestOut.length + ", should be " +
                    mozillaDigest.getDigestLength(), TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        keyID = new TPSBuffer(mozillaDigestOut);

        CMS.debug("TPSEnrollProcessor.makeKeyFromPublicKeyInfo: " + keyID.toHexString());

        return keyID;
    }

    public static void main(String[] args) {
    }

}
