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

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.server.tps.engine.TPS;
import org.dogtagpki.tps.apdu.APDU;
import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.apdu.GetData;
import org.dogtagpki.tps.apdu.GetStatus;
import org.dogtagpki.tps.apdu.Select;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.BeginOp;
import org.dogtagpki.tps.msg.TokenPDURequest;
import org.dogtagpki.tps.msg.TokenPDUResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

public abstract class TPSProcessor {

    public enum TPS_Status {
        STATUS_NO_ERROR,
        STATUS_ERROR_SNAC,
        STATUS_ERROR_SEC_INIT_UPDATE,
        STATUS_ERROR_CREATE_CARDMGR,
        STATUS_ERROR_MAC_RESET_PIN_PDU,
        STATUS_ERROR_MAC_CERT_PDU,
        STATUS_ERROR_MAC_LIFESTYLE_PDU,
        STATUS_ERROR_MAC_ENROLL_PDU,
        STATUS_ERROR_READ_OBJECT_PDU,
        STATUS_ERROR_BAD_STATUS,
        STATUS_ERROR_CA_RESPONSE,
        STATUS_ERROR_READ_BUFFER_OVERFLOW,
        STATUS_ERROR_TOKEN_RESET_PIN_FAILED,
        STATUS_ERROR_CONNECTION,
        STATUS_ERROR_LOGIN,
        STATUS_ERROR_DB,
        STATUS_ERROR_TOKEN_DISABLED,
        STATUS_ERROR_SECURE_CHANNEL,
        STATUS_ERROR_MISCONFIGURATION,
        STATUS_ERROR_UPGRADE_APPLET,
        STATUS_ERROR_KEY_CHANGE_OVER,
        STATUS_ERROR_EXTERNAL_AUTH,
        STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND,
        STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND,
        STATUS_ERROR_PUBLISH,
        STATUS_ERROR_LDAP_CONN,
        STATUS_ERROR_DISABLED_TOKEN,
        STATUS_ERROR_NOT_PIN_RESETABLE,
        STATUS_ERROR_CONN_LOST,
        STATUS_ERROR_CREATE_TUS_TOKEN_ENTRY,
        STATUS_ERROR_NO_SUCH_TOKEN_STATE,
        STATUS_ERROR_NO_SUCH_LOST_REASON,
        STATUS_ERROR_UNUSABLE_TOKEN_KEYCOMPROMISE,
        STATUS_ERROR_INACTIVE_TOKEN_NOT_FOUND,
        STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN,
        STATUS_ERROR_CONTACT_ADMIN,
        STATUS_ERROR_RECOVERY_IS_PROCESSED,
        STATUS_ERROR_RECOVERY_FAILED,
        STATUS_ERROR_NO_OPERATION_ON_LOST_TOKEN,
        STATUS_ERROR_KEY_ARCHIVE_OFF,
        STATUS_ERROR_NO_TKS_CONNID,
        STATUS_ERROR_UPDATE_TOKENDB_FAILED,
        STATUS_ERROR_REVOKE_CERTIFICATES_FAILED,
        STATUS_ERROR_NOT_TOKEN_OWNER,
        STATUS_ERROR_RENEWAL_IS_PROCESSED,
        STATUS_ERROR_RENEWAL_FAILED
    };

    public static final int RESULT_NO_ERROR = 0;
    public static final int RESULT_ERROR = -1;

    public static final int CPLC_DATA_SIZE = 47;
    public static final int CPLC_MSN_INDEX = 41;
    public static final int CPLC_MSN_SIZE  = 4;

    public TPSProcessor() {
    }

    protected TPSBuffer extractTokenNSM(TPSBuffer cplc_data) {
        if (cplc_data == null || cplc_data.size() < CPLC_DATA_SIZE) {
            CMS.debug("TPS_Processor.extractTokenMSN: cplc_data: invalid length.");
            return null;
        }

        TPSBuffer token_msn = cplc_data.substr(CPLC_MSN_INDEX, CPLC_MSN_SIZE);

        return token_msn;

    }

    protected TPSBuffer extractTokenCUID(TPSBuffer cplc_data) {

        if (cplc_data == null || cplc_data.size() < 47) {
            CMS.debug("TPS_Processor.extractTokenCUID: cplc_data: invalid length.");
            return null;
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

    protected int SelectCardManager(TPSSession session, String prefix, String tokenType) {
        //ToDo
        return 0;
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
     */

    protected int SelectApplet(TPSSession session, byte p1, byte p2, TPSBuffer aid)  {

        CMS.debug("In TPS_Processor.SelectApplet.");
        int rc = RESULT_ERROR;

        //Test data until we can read the CFG

        if (aid.size() == 0) {
            return RESULT_ERROR;
        }

        Select select_apdu = new Select(p1, p2, aid);

        APDUResponse respApdu = HandleAPDURequest(session, select_apdu);

        if(checkTokenPDUResponse(respApdu) == true) {
            rc = RESULT_NO_ERROR;
        }

        return rc;

    }

    protected TPSBuffer GetStatus(TPSSession session) {

        CMS.debug("In TPS_Processor.GetStatus.");

        TPSBuffer result = null;

        GetStatus get_status_apdu = new GetStatus();

        APDUResponse respApdu = HandleAPDURequest(session, get_status_apdu);

        if( respApdu != null) {
            result = respApdu.getData();
        }

        return result;
    }

    protected APDUResponse HandleAPDURequest(TPSSession session, APDU apdu) {
        APDUResponse response = null;

        if(session == null || apdu == null) {
            return response;
        }

        TokenPDURequest request_msg = new TokenPDURequest(apdu);

        try {
            session.write(request_msg);
        } catch (Exception e) {
            CMS.debug("TPS_Processor.HandleAPDURequest failed WriteMsg: " + e.toString());
            return response;

        }

        TokenPDUResponse response_msg = null;

        try {
            response_msg = (TokenPDUResponse) session.read();
        } catch (Exception e) {
            CMS.debug("TPS_Processor.HandleAPDURequest failed ReadMsg: " + e.toString());
            return response;

        }

        response = response_msg.getResponseAPDU();

        if (checkTokenPDUResponse(response) == true) {
            CMS.debug("TPS_Processor.HandleAPDURequest : apdu response is success");
        } else {
            CMS.debug("TPS_Processor.HandleAPDURequest: apdu response is failure.");
        }

        return response;

    }

    protected TPSBuffer GetCplcData(TPSSession session) {
        CMS.debug("In TPS_Processor.GetData");
        TPSBuffer result = null;

        GetData get_data_apdu = new GetData();

        APDUResponse respApdu = HandleAPDURequest(session, get_data_apdu);

        result = respApdu.getData();

        return result;

    }

    protected TPS_Status Format(TPSSession session, BeginOp message) throws EBaseException {

        IConfigStore configStore = CMS.getConfigStore();

        String CardManagerAID = null;
        String NetKeyAID = null;

        String External_Reg_Cfg = TPS.CFG_EXTERNAL_REG + "." + "enable";
        boolean isExternalReg = false;

        try {
            CardManagerAID = configStore.getString(TPS.CFG_APPLET_CARDMGR_INSTANCE_AID,
                    TPS.CFG_DEF_CARDMGR_INSTANCE_AID);
            NetKeyAID = configStore.getString(TPS.CFG_APPLET_NETKEY_INSTANCE_AID, TPS.CFG_DEF_NETKEY_INSTANCE_AID);
            CMS.debug("In TPS_Processor.Format. CardManagerAID: " + CardManagerAID + " NetKeyAID: " + NetKeyAID);
            this.isExternalReg = configStore.getBoolean(External_Reg_Cfg,false);
            CMS.debug("In TPS_Processor.Format isExternalReg: " + isExternalReg);
        } catch (EBaseException e1) {
            CMS.debug("In TPS_Processor.Format: Error obtaining config values.");
            e1.printStackTrace();
            throw new EBaseException("TPS error getting config values from config store.");
        }

        TPS_Status ret = TPS_Status.STATUS_NO_ERROR;

        TPSBuffer aidBuf = new TPSBuffer(CardManagerAID);

        int select_rc = RESULT_NO_ERROR;

        select_rc = SelectApplet(session, (byte) 0x04, (byte) 0x00, aidBuf);

        if (select_rc ==  RESULT_ERROR) {
            ret = TPS_Status.STATUS_ERROR_SECURE_CHANNEL;
            return ret;
        }

        TPSBuffer cplc_data = GetCplcData(session);

        if (cplc_data == null) {
            ret = TPS_Status.STATUS_ERROR_SECURE_CHANNEL;
            return ret;
        } else {
            CMS.debug("cplc_data: " + cplc_data.toString());
        }

        TPSBuffer token_cuid = extractTokenCUID(cplc_data);

        String cuid = null;

        if (token_cuid != null) {
            cuid = token_cuid.toHexString();
            CMS.debug("TPS_Processor.Format: token_cuid str: " + cuid);
        } else {
            ret = TPS_Status.STATUS_ERROR_SECURE_CHANNEL;
            return ret;
        }

        TPSBuffer token_msn = extractTokenNSM(cplc_data);

        String msn = null;

        if (token_msn != null) {
            msn = token_msn.toHexString();
            CMS.debug("TPS_Processor.Format: token_msn str: " + msn);
        }

        /**
         * Checks if the netkey has the required applet version.
         */

        TPSBuffer netkeyAid = new TPSBuffer(NetKeyAID);

        select_rc = RESULT_NO_ERROR;

        select_rc = SelectApplet(session, (byte) 0x04, (byte) 0x00, netkeyAid);

        if (select_rc == RESULT_ERROR) {
            ret = TPS_Status.STATUS_ERROR_SECURE_CHANNEL;
            return ret;
        }

        TPSBuffer status = GetStatus(session);

        byte major_version = 0x0;
        byte minor_version = 0x0;
        byte app_major_version = 0x0;
        byte app_minor_version = 0x0;

        if (status != null) {
            CMS.debug("TPS_Processor.Format: status: " + status.toHexString());
            major_version = status.at(0);
            minor_version = status.at(1);
            app_major_version = status.at(2);
            app_minor_version = status.at(3);
            CMS.debug("TPS_Processor.Format: major_version " + major_version + " minor_version: " + minor_version
                    + " app_major_version: " + app_major_version + " app_minor_version: " + app_minor_version);

        } else {
            ret = TPS_Status.STATUS_ERROR_SECURE_CHANNEL;
        }

        if(isExternalReg) {
            //ToDo, do some external Reg stuff along with authentication
        } else {
            //ToDo, Do some authentication
        }

        return ret;
    }

    public static int statusToInt(TPS_Status status) {

        int result = 0;

        switch (status) {
        case STATUS_NO_ERROR:
            result = 0;
            break;
        case STATUS_ERROR_SNAC:
            result = 1;
            break;
        case STATUS_ERROR_SEC_INIT_UPDATE:
            result = 2;
            break;
        case STATUS_ERROR_CREATE_CARDMGR:
            result = 3;
            break;
        case STATUS_ERROR_MAC_RESET_PIN_PDU:
            result = 4;
            break;
        case STATUS_ERROR_MAC_CERT_PDU:
            result = 5;
            break;
        case STATUS_ERROR_MAC_LIFESTYLE_PDU:
            result = 6;
            break;
        case STATUS_ERROR_MAC_ENROLL_PDU:
            result = 7;
            break;
        case STATUS_ERROR_READ_OBJECT_PDU:
            result = 8;
            break;
        case STATUS_ERROR_BAD_STATUS:
            result = 9;
            break;
        case STATUS_ERROR_CA_RESPONSE:
            result = 10;
            break;
        case STATUS_ERROR_READ_BUFFER_OVERFLOW:
            result = 11;
            break;
        case STATUS_ERROR_TOKEN_RESET_PIN_FAILED:
            result = 12;
            break;
        case STATUS_ERROR_CONNECTION:
            result = 13;
            break;
        case STATUS_ERROR_LOGIN:
            result = 14;
            break;
        case STATUS_ERROR_DB:
            result = 15;
            break;
        case STATUS_ERROR_TOKEN_DISABLED:
            result = 16;
            break;
        case STATUS_ERROR_SECURE_CHANNEL:
            result = 17;
            break;
        case STATUS_ERROR_MISCONFIGURATION:
            result = 18;
            break;
        case STATUS_ERROR_UPGRADE_APPLET:
            result = 19;
            break;
        case STATUS_ERROR_KEY_CHANGE_OVER:
            result = 20;
            break;
        case STATUS_ERROR_EXTERNAL_AUTH:
            result = 21;
            break;
        case STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND:
            result = 22;
            break;
        case STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND:
            result = 23;
            break;
        case STATUS_ERROR_PUBLISH:
            result = 24;
            break;
        case STATUS_ERROR_LDAP_CONN:
            result = 25;
            break;
        case STATUS_ERROR_DISABLED_TOKEN:
            result = 26;
            break;
        case STATUS_ERROR_NOT_PIN_RESETABLE:
            result = 27;
            break;
        case STATUS_ERROR_CONN_LOST:
            result = 28;
            break;
        case STATUS_ERROR_CREATE_TUS_TOKEN_ENTRY:
            result = 29;
            break;
        case STATUS_ERROR_NO_SUCH_TOKEN_STATE:
            result = 30;
            break;
        case STATUS_ERROR_NO_SUCH_LOST_REASON:
            result = 31;
            break;
        case STATUS_ERROR_UNUSABLE_TOKEN_KEYCOMPROMISE:
            result = 32;
            break;
        case STATUS_ERROR_INACTIVE_TOKEN_NOT_FOUND:
            result = 33;
            break;
        case STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN:
            result = 34;
            break;
        case STATUS_ERROR_CONTACT_ADMIN:
            result = 35;
            break;
        case STATUS_ERROR_RECOVERY_IS_PROCESSED:
            result = 36;
            break;
        case STATUS_ERROR_RECOVERY_FAILED:
            result = 37;
            break;
        case STATUS_ERROR_NO_OPERATION_ON_LOST_TOKEN:
            result = 38;
            break;
        case STATUS_ERROR_KEY_ARCHIVE_OFF:
            result = 39;
            break;
        case STATUS_ERROR_NO_TKS_CONNID:
            result = 40;
            break;
        case STATUS_ERROR_UPDATE_TOKENDB_FAILED:
            result = 41;
            break;
        case STATUS_ERROR_REVOKE_CERTIFICATES_FAILED:
            result = 42;
            break;
        case STATUS_ERROR_NOT_TOKEN_OWNER:
            result = 43;
            break;
        case STATUS_ERROR_RENEWAL_IS_PROCESSED:
            result = 44;
            break;
        case STATUS_ERROR_RENEWAL_FAILED:
            result = 45;
            break;
        default:
            break;
        }

        return result;

    }

    protected boolean checkTokenPDUResponse(APDUResponse response) {

        boolean result = false;

        if (response == null)
            return result;

        byte sw1 = response.getSW1();
        byte sw2 = response.GetSW2();

        int int1 = sw1 & 0xff;
        int int2 = sw2 & 0xff;

        CMS.debug("checkTokenPDUResponse: sw1: " +  "0x" + Util.intToHex(int1) + " sw2: " + "0x" + Util.intToHex(int2));

        if (sw1 == (byte) 0x90 && sw2 == 0x0)
            result = true;

        return result;
    }


    private boolean isExternalReg = false;

    public boolean getIsExternalReg() {
        return isExternalReg;
    }

    public static void main(String[] args) {
    }

    public TPS_Status Process(TPSSession session, BeginOp beginMsg) throws EBaseException {
        return TPS_Status.STATUS_NO_ERROR;
    }


}
