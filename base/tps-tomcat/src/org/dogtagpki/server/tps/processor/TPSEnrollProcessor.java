package org.dogtagpki.server.tps.processor;

import java.io.IOException;
import java.util.zip.DataFormatException;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.authentication.TPSAuthenticator;
import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.server.tps.main.ObjectSpec;
import org.dogtagpki.server.tps.main.PKCS11Obj;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU.SecurityLevel;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOpMsg;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

public class TPSEnrollProcessor extends TPSProcessor {

    public enum TokenKeyType {
        KEY_TYPE_ENCRYPTION,
        KEY_TYPE_SIGNING,
        KEY_TYPE_SIGNING_AND_ENCRYPTION
    };

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

        checkAndHandlePinReset();

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

        //ToDo: Add token to token db

        statusUpdate(15, "PROGRESS_PROCESS_PROFILE");

        EnrolledCertsInfo certsInfo = new EnrolledCertsInfo();
        certsInfo.setWrappedChallenge(wrappedChallenge);
        certsInfo.setPlaintextChallenge(plaintextChallenge);
        certsInfo.setPKCS11Obj(pkcs11objx);

        generateCertificates(certsInfo, channel, appletInfo);

        throw new TPSException("TPSEnrollProcessor.enroll: Failed to enroll token!",
                TPSStatus.STATUS_ERROR_CONTACT_ADMIN);

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
                    CMS.debug("TPSEnrollProcessor.checkAndAuthenticateUser: auth passed: userid: " + authToken.get("userid"));
                } catch (Exception e) {
                    // all exceptions are considered login failure
                    CMS.debug("TPSEnrollProcessor.checkAndAuthenticateUser:: authentication exception thrown: " + e);
                    throw new TPSException("TPS error user authentication failed.",
                            TPSStatus.STATUS_ERROR_LOGIN);
                }
            } else {
                throw new TPSException("TPSEnrollProcessor.checkAndAuthenticateUser: TPS enrollment must have authentication enabled.",
                        TPSStatus.STATUS_ERROR_LOGIN);

            }

        }
    }

    private void checkAndHandlePinReset() {
        // TODO Auto-generated method stub

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

        PKCS11Obj pkcs11objx = new PKCS11Obj();
        do {
            objects = listObjects(seq);

            if (objects == null) {
                seq = 0;
            } else {
                seq = 1; // get next entry

                TPSBuffer objectID = objects.substr(0, 4);
                TPSBuffer objectLen = objects.substr(4, 4);

                long objectIDVal = objectID.getLongFrom4Bytes(0);

                long objectLenVal = objectLen.getLongFrom4Bytes(0);

                TPSBuffer obj = channel.readObject(objectID, 0, (int) objectLenVal);

                if ((char) obj.at(0) == 'z' && obj.at(1) == 0x0) {
                    pkcs11objx = PKCS11Obj.parse(obj, 0);
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
        }

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

            CertEnrollInfo cEnrollInfo = new CertEnrollInfo();

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

            int certsStartProgress = cEnrollInfo.getStartProgressValue();
            int certsEndProgress = cEnrollInfo.getEndProgressValue();
            int currentCertIndex = certsInfo.getCurrentCertIndex();
            int totalNumCerts = certsInfo.getNumCertsToEnroll();

            int progressBlock = (certsEndProgress - certsStartProgress) / totalNumCerts;

            int startCertProgValue = certsStartProgress + currentCertIndex * progressBlock;

            int endCertProgValue = startCertProgValue + progressBlock;

            cEnrollInfo.setStartProgressValue(startCertProgValue);
            cEnrollInfo.setEndProgressValue(endCertProgValue);

            enrollOneCertificate(certsInfo, cEnrollInfo, aInfo, channel);

        } catch (EBaseException e) {

            throw new TPSException(
                    "TPSEnrollProcessor.generateCertificate: Internal error finding config value: " + e,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

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

            TPSBuffer public_key = channel.readObject(iobuf, 0, size);

            parsePublicKeyInfo(public_key);

            //ToDo: Finish the rest of this

        }

        statusUpdate(cEnrollInfo.getEndProgressValue(), "PROGRESS_ENROLL_CERT");

    }

    //We don't know what to return for this as of yet, make it void for now.
    private void parsePublicKeyInfo(TPSBuffer public_key) throws TPSException {

        if (public_key == null) {
            throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CMS.debug("TPSEnrollProcessor.enrollOneCertificate: public key returned from token: "
                + public_key.toHexString());

        TPSBuffer pKeyBlob = public_key.substr(2);
        //Check for bad blob here:

        if (pKeyBlob == null) {
            throw new TPSException("TPSEnrollProcessor.parsePublicKeyBlob: Bad input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //ToDo: finish this
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

    public static void main(String[] args) {
    }

}
