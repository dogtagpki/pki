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
import java.util.Map;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.channel.SecureChannel.SecurityLevel;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.apdu.APDU;
import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.apdu.GetData;
import org.dogtagpki.tps.apdu.GetStatus;
import org.dogtagpki.tps.apdu.GetVersion;
import org.dogtagpki.tps.apdu.Select;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.BeginOp;
import org.dogtagpki.tps.msg.EndOp.TPSStatus;
import org.dogtagpki.tps.msg.TokenPDURequest;
import org.dogtagpki.tps.msg.TokenPDUResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;

public class TPSProcessor {

    public static final int RESULT_NO_ERROR = 0;
    public static final int RESULT_ERROR = -1;

    public static final int CPLC_DATA_SIZE = 47;
    public static final int CPLC_MSN_INDEX = 41;
    public static final int CPLC_MSN_SIZE = 4;

    private boolean isExternalReg;

    private TPSSession session;
    private String selectedTokenType;

    public TPSProcessor(TPSSession session) {
        setSession(session);
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

    protected void setSelectedTokenType(String theTokenType) {

        if (theTokenType == null) {
            throw new NullPointerException("TPSProcessor.setSelectedTokenType: Attempt to set invalid null token type!");
        }
        selectedTokenType = theTokenType;
    }

    protected String getSelectedTokenType() {
        return selectedTokenType;
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

        Select select_apdu = new Select(p1, p2, aid);

        //return the Response because the caller can
        //decide what to do, not every failure is fatal.
        //For instance the coolkey applet may not yet exist.
        return handleAPDURequest(select_apdu);

    }

    protected TPSBuffer getStatus() throws IOException, TPSException {

        CMS.debug("In TPS_Processor.GetStatus.");

        GetStatus get_status_apdu = new GetStatus();

        return handleAPDURequest(get_status_apdu).getData();
    }

    protected APDUResponse handleAPDURequest(APDU apdu) throws IOException, TPSException {

        if (apdu == null) {
            throw new TPSException("TPSProcessor.handleAPDURequest: invalid incoming apdu!");
        }

        TokenPDURequest request_msg = new TokenPDURequest(apdu);

        try {
            session.write(request_msg);
        } catch (IOException e) {
            CMS.debug("TPS_Processor.HandleAPDURequest failed WriteMsg: " + e.toString());
            throw e;

        }

        TokenPDUResponse response_msg = null;

        try {
            response_msg = (TokenPDUResponse) session.read();
        } catch (IOException e) {
            CMS.debug("TPS_Processor.HandleAPDURequest failed ReadMsg: " + e.toString());
            throw e;

        }

        return response_msg.getResponseAPDU();
    }

    protected TPSBuffer getCplcData() throws IOException, TPSException {
        CMS.debug("In TPS_Processor.GetData");

        GetData get_data_apdu = new GetData();

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

    protected TPSBuffer getAppletVersion() throws IOException, TPSException {
        //We return null if no applet present
        // This is not an error, the token can be blank.

        CMS.debug("In TPSProcessor.getAppletVersion");

        GetVersion get_version_apdu = new GetVersion();

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

    protected String upgradeApplet(String operation, String new_version, SecurityLevel securityLevel,
            Map<String, String> extensions, int startProgress, int endProgress) throws TPSException {

        String newVersion = null;
        boolean appletUpgraded = false;

        String directory = getAppletDirectory(operation);

        CMS.debug("TPSProcessor.upgradeApplet: applet target directory: " + directory);

        //ToDo actually finish this later.
        if (appletUpgraded == false) {
            throw new TPSException("TPSProcessor.upgradeApplet: Error upgrading applet",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        return newVersion;
    }

    protected void format(BeginOp message) throws TPSException, IOException {

        IConfigStore configStore = CMS.getConfigStore();

        String CardManagerAID = null;
        String NetKeyAID = null;
        String appletVersion = null;

        TPSSubsystem tps = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        TPSEngine engine = tps.getEngine();

        String External_Reg_Cfg = TPSEngine.CFG_EXTERNAL_REG + "." + "enable";
        boolean isExternalReg = false;

        try {
            //These defaults are well known, it is safe to use them.
            CardManagerAID = configStore.getString(TPSEngine.CFG_APPLET_CARDMGR_INSTANCE_AID,
                    TPSEngine.CFG_DEF_CARDMGR_INSTANCE_AID);
            NetKeyAID = configStore.getString(TPSEngine.CFG_APPLET_NETKEY_INSTANCE_AID,
                    TPSEngine.CFG_DEF_NETKEY_INSTANCE_AID);
            CMS.debug("In TPS_Processor.Format. CardManagerAID: " + CardManagerAID + " NetKeyAID: " + NetKeyAID);
            this.isExternalReg = configStore.getBoolean(External_Reg_Cfg, false);
            CMS.debug("In TPS_Processor.Format isExternalReg: " + isExternalReg);
        } catch (EBaseException e1) {
            CMS.debug("TPS_Processor.Format: Internal Error obtaining mandatory config values. Error: " + e1);
            throw new TPSException("TPS error getting config values from config store.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        TPSBuffer aidBuf = new TPSBuffer(CardManagerAID);

        APDUResponse select = selectApplet((byte) 0x04, (byte) 0x00, aidBuf);

        if (!select.checkResult()) {
            throw new TPSException("TPSProcessor.format: Can't selelect the card manager!");
        }

        TPSBuffer cplc_data = getCplcData();
        CMS.debug("cplc_data: " + cplc_data.toString());

        TPSBuffer token_cuid = extractTokenCUID(cplc_data);
        String cuid = token_cuid.toHexString();

        TPSBuffer token_msn = extractTokenMSN(cplc_data);
        String msn = token_msn.toHexString();

        /**
         * Checks if the netkey has the required applet version.
         */

        TPSBuffer netkeyAid = new TPSBuffer(NetKeyAID);

        // We don't care if the above fails now. getStatus will determine outcome.

        select = selectApplet((byte) 0x04, (byte) 0x00, netkeyAid);

        CMS.debug("TPSProcessor.format: First time select netkey applet: " + select.checkResult());

        TPSBuffer token_status = getStatus();

        byte major_version = 0x0;
        byte minor_version = 0x0;
        byte app_major_version = 0x0;
        byte app_minor_version = 0x0;

        CMS.debug("TPS_Processor.format: status: " + token_status.toHexString());
        if (token_status.size() >= 4) {
            major_version = token_status.at(0);
            minor_version = token_status.at(1);
            app_major_version = token_status.at(2);
            app_minor_version = token_status.at(3);
        }
        CMS.debug("TPSProcessor.format: major_version " + major_version + " minor_version: " + minor_version
                + " app_major_version: " + app_major_version + " app_minor_version: " + app_minor_version);

        if (isExternalReg) {
            //ToDo, do some external Reg stuff along with authentication
        } else {
            //ToDo, Do some authentication
        }

        String tokenType = getTokenType(TPSEngine.OP_FORMAT_PREFIX, major_version, minor_version, cuid, msn,
                message.getExtensions());

        CMS.debug("TPS_Processor.format: calculated tokenType: " + tokenType);

        //Now check provided profile

        checkProfileStateOK();

        if (engine.isTokenPresent(cuid)) {
            //ToDo

        } else {
            checkAllowUnknownToken(TPSEngine.OP_FORMAT_PREFIX);
        }

        TPSBuffer build_id = getAppletVersion();

        if (build_id == null) {
            checkAllowNoAppletToken(TPSEngine.OP_FORMAT_PREFIX);
        } else {
            appletVersion = Integer.toHexString(app_major_version) + "." + Integer.toHexString(app_minor_version) + "."
                    + build_id.toHexString();
        }

        String appletRequiredVersion = checkForAppletUpgrade(TPSEngine.OP_FORMAT_PREFIX);

        CMS.debug("TPSProcessor.format: appletVersion found: " + appletVersion + "requiredVersion: "
                + appletRequiredVersion);

        SecurityLevel secLevel = SecurityLevel.SECURE_MSG_MAC_ENC;

        String newKeyVersion = upgradeApplet(TPSEngine.OP_FORMAT_PREFIX, appletRequiredVersion, secLevel,
                message.getExtensions(),
                10, 90);

        CMS.debug("TPSProcessor.format: upgraded aplet version: " + newKeyVersion);
    }

    void checkProfileStateOK() throws TPSException {

        IConfigStore configStore = CMS.getConfigStore();

        String profileConfig = "config.Profiles." + selectedTokenType + ".state";
        String profileState = null;

        try {
            profileState = configStore.getString(profileConfig, TPSEngine.CFG_ENABLED);
        } catch (EBaseException e) {
            //Default TPSException will return a "contact admin" error code.
            throw new TPSException(
                    "TPSProcessor.checkProfileStateOK: internal error in getting profile state from config.");
        }

        if (!profileState.equals(TPSEngine.CFG_ENABLED)) {
            CMS.debug("TPSProcessor.checkProfileStateOK: profile specifically disabled.");
            throw new TPSException("TPSProcessor.checkProfileStateOK: profile disabled!");
        }

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

    protected String checkForAppletUpgrade(String operation) throws TPSException {
        String requiredVersion = null;
        IConfigStore configStore = CMS.getConfigStore();

        String appletRequiredConfig = operation + "." + selectedTokenType + "."
                + TPSEngine.CFG_APPLET_UPDATE_REQUIRED_VERSION;

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

        String unknownConfig = operation + "." + TPSEngine.CFG_ALLOW_UNKNOWN_TOKEN;

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

    public boolean getIsExternalReg() {
        return isExternalReg;
    }

    public void process(BeginOp beginMsg) throws TPSException, IOException {
        format(beginMsg);
    }

    /* Return calculated token profile type.
    *
    */
    public String getTokenType(String prefix, int major_version, int minor_version, String cuid, String msn,
            Map<String, String> extensions) throws TPSException {
        String tokenType = null;
        String mappingOrder = null;

        if (selectedTokenType != null) {
            CMS.debug("TPSProcessor.getTokenType: Calling this more than once. This is not needed!");
            return selectedTokenType;
        }

        IConfigStore configStore = CMS.getConfigStore();

        String configName = prefix + "." + TPSEngine.CFG_PROFILE_MAPPING_ORDER;

        try {
            mappingOrder = configStore.getString(configName);
        } catch (EPropertyNotFound e) {
            throw new TPSException(
                    "TPSProcessor.getTokenType: Token Type configuration incorrect! Mising mapping order!",
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);

        } catch (EBaseException e1) {
            //The whole feature won't work if this is wrong.
            throw new TPSException(
                    "TPSProcessor.getTokenType: Internal error obtaining config value.!",
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
        }

        String targetTokenType = null;

        for (String mappingId : mappingOrder.split(",")) {

            CMS.debug("TPS_Processor::GetTokenType:  mapping: " + mappingId);

            String mappingConfigName = prefix + ".mapping." + mappingId + ".target.tokenType";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            //We need this to exist.
            try {
                targetTokenType = configStore.getString(mappingConfigName);
            } catch (EPropertyNotFound e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Token Type configuration incorrect! No target token type config value found! Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);

            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenType";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            //For this and remaining cases, it is not automatically an error if we don't get anything back
            // from the config.
            try {
                tokenType = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);

            }

            CMS.debug("TPS_Processor::GetTokenType:  targetTokenType: " + targetTokenType);

            if (tokenType != null && tokenType.length() > 0) {

                if (extensions == null) {
                    continue;
                }

                String eTokenType = extensions.get("tokenType");
                if (eTokenType == null) {
                    continue;
                }

                if (!eTokenType.equals(tokenType)) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenATR";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            String tokenATR = null;

            try {
                tokenATR = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("TPS_Processor::GetTokenType:  tokenATR: " + tokenATR);

            if (tokenATR != null && tokenATR.length() > 0) {
                if (extensions == null) {
                    continue;
                }

                String eTokenATR = extensions.get("tokenATR");

                if (eTokenATR == null) {
                    continue;
                }

                if (!eTokenATR.equals(tokenATR)) {
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.start";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            String tokenCUIDStart = null;

            try {
                tokenCUIDStart = configStore.getString(mappingConfigName, null);

            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("TPS_Processor::GetTokenType:  tokenCUIDStart: " + tokenCUIDStart);

            if (tokenCUIDStart != null && tokenCUIDStart.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDStart.length() != 20) {
                    continue;
                }

                if (cuid.compareTo(tokenCUIDStart) < 0) {
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.tokenCUID.end";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            String tokenCUIDEnd = null;
            try {
                tokenCUIDEnd = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("TPS_Processor::GetTokenType:  tokenCUIDEnd: " + tokenCUIDEnd);

            if (tokenCUIDEnd != null && tokenCUIDEnd.length() > 0) {
                if (cuid == null) {
                    continue;
                }

                if (tokenCUIDEnd.length() != 20) {
                    continue;
                }

                if (cuid.compareTo(tokenCUIDEnd) > 0) {
                    continue;
                }

            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMajorVersion";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            String majorVersion = null;
            String minorVersion = null;

            try {
                majorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }

            CMS.debug("TPS_Processor::GetTokenType:  majorVersion: " + majorVersion);
            if (majorVersion != null && majorVersion.length() > 0) {

                int major = Integer.parseInt(majorVersion);

                if (major != major_version) {
                    continue;
                }
            }

            mappingConfigName = prefix + ".mapping." + mappingId + ".filter.appletMinorVersion";

            CMS.debug("TPS_Processor::GetTokenType:  mappingConfigName: " + mappingConfigName);

            try {
                minorVersion = configStore.getString(mappingConfigName, null);
            } catch (EBaseException e) {
                throw new TPSException(
                        "TPSProcessor.getTokenType: Internal error obtaining config value. Config: "
                                + mappingConfigName,
                        TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
            }
            CMS.debug("TPS_Processor::GetTokenType:  minorVersion " + minorVersion);

            if (minorVersion != null && minorVersion.length() > 0) {

                int minor = Integer.parseInt(minorVersion);

                if (minor != minor_version) {
                    continue;
                }
            }

            //if we make it this far, we have a token type
            CMS.debug("TPS_Processor::GetTokenType: Selected Token type: " + targetTokenType);
            break;
        }

        if (targetTokenType == null) {
            CMS.debug("TPSProcessor.getTokenType: end found: " + targetTokenType);
            throw new TPSException("TPSProcessor.getTokenType: Can't find token type!",
                    TPSStatus.STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND);
        }

        //Set this once, it won't change for this session.
        setSelectedTokenType(targetTokenType);
        return targetTokenType;

    }

    public static void main(String[] args) {
    }

}
