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
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.apdu.APDU;
import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.apdu.GetData;
import org.dogtagpki.tps.apdu.GetStatus;
import org.dogtagpki.tps.apdu.Select;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.BeginOp;
import org.dogtagpki.tps.msg.EndOp.TPSStatus;
import org.dogtagpki.tps.msg.TokenPDURequest;
import org.dogtagpki.tps.msg.TokenPDUResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

public abstract class TPSProcessor {

    public static final int RESULT_NO_ERROR = 0;
    public static final int RESULT_ERROR = -1;

    public static final int CPLC_DATA_SIZE = 47;
    public static final int CPLC_MSN_INDEX = 41;
    public static final int CPLC_MSN_SIZE = 4;

    private boolean isExternalReg = false;

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

    protected int selectCardManager(TPSSession session, String prefix, String tokenType) {
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

    protected int selectApplet(TPSSession session, byte p1, byte p2, TPSBuffer aid) {

        CMS.debug("In TPS_Processor.SelectApplet.");
        int rc = RESULT_ERROR;

        //Test data until we can read the CFG

        if (aid.size() == 0) {
            return RESULT_ERROR;
        }

        Select select_apdu = new Select(p1, p2, aid);

        APDUResponse respApdu = handleAPDURequest(session, select_apdu);

        if (checkTokenPDUResponse(respApdu) == true) {
            rc = RESULT_NO_ERROR;
        }

        return rc;

    }

    protected TPSBuffer getStatus(TPSSession session) {

        CMS.debug("In TPS_Processor.GetStatus.");

        TPSBuffer result = null;

        GetStatus get_status_apdu = new GetStatus();

        APDUResponse respApdu = handleAPDURequest(session, get_status_apdu);

        if (respApdu != null) {
            result = respApdu.getData();
        }

        return result;
    }

    protected APDUResponse handleAPDURequest(TPSSession session, APDU apdu) {
        APDUResponse response = null;

        if (session == null || apdu == null) {
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

    protected TPSBuffer getCplcData(TPSSession session) {
        CMS.debug("In TPS_Processor.GetData");
        TPSBuffer result = null;

        GetData get_data_apdu = new GetData();

        APDUResponse respApdu = handleAPDURequest(session, get_data_apdu);

        result = respApdu.getData();

        return result;

    }

    protected TPSStatus format(TPSSession session, BeginOp message) throws EBaseException {

        IConfigStore configStore = CMS.getConfigStore();

        String CardManagerAID = null;
        String NetKeyAID = null;

        String External_Reg_Cfg = TPSEngine.CFG_EXTERNAL_REG + "." + "enable";
        boolean isExternalReg = false;

        try {
            CardManagerAID = configStore.getString(TPSEngine.CFG_APPLET_CARDMGR_INSTANCE_AID,
                    TPSEngine.CFG_DEF_CARDMGR_INSTANCE_AID);
            NetKeyAID = configStore.getString(TPSEngine.CFG_APPLET_NETKEY_INSTANCE_AID,
                    TPSEngine.CFG_DEF_NETKEY_INSTANCE_AID);
            CMS.debug("In TPS_Processor.Format. CardManagerAID: " + CardManagerAID + " NetKeyAID: " + NetKeyAID);
            this.isExternalReg = configStore.getBoolean(External_Reg_Cfg, false);
            CMS.debug("In TPS_Processor.Format isExternalReg: " + isExternalReg);
        } catch (EBaseException e1) {
            CMS.debug("In TPS_Processor.Format: Error obtaining config values.");
            e1.printStackTrace();
            throw new EBaseException("TPS error getting config values from config store.");
        }

        TPSStatus ret = TPSStatus.STATUS_NO_ERROR;

        TPSBuffer aidBuf = new TPSBuffer(CardManagerAID);

        int select_rc = RESULT_NO_ERROR;

        select_rc = selectApplet(session, (byte) 0x04, (byte) 0x00, aidBuf);

        if (select_rc == RESULT_ERROR) {
            ret = TPSStatus.STATUS_ERROR_SECURE_CHANNEL;
            return ret;
        }

        TPSBuffer cplc_data = getCplcData(session);

        if (cplc_data == null) {
            ret = TPSStatus.STATUS_ERROR_SECURE_CHANNEL;
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
            ret = TPSStatus.STATUS_ERROR_SECURE_CHANNEL;
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

        select_rc = selectApplet(session, (byte) 0x04, (byte) 0x00, netkeyAid);

        if (select_rc == RESULT_ERROR) {
            ret = TPSStatus.STATUS_ERROR_SECURE_CHANNEL;
            return ret;
        }

        TPSBuffer status = getStatus(session);

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
            ret = TPSStatus.STATUS_ERROR_SECURE_CHANNEL;
        }

        if (isExternalReg) {
            //ToDo, do some external Reg stuff along with authentication
        } else {
            //ToDo, Do some authentication
        }

        return ret;
    }

    protected boolean checkTokenPDUResponse(APDUResponse response) {

        boolean result = false;

        if (response == null)
            return result;

        byte sw1 = response.getSW1();
        byte sw2 = response.getSW2();

        int int1 = sw1 & 0xff;
        int int2 = sw2 & 0xff;

        CMS.debug("checkTokenPDUResponse: sw1: " + "0x" + Util.intToHex(int1) + " sw2: " + "0x" + Util.intToHex(int2));

        if (sw1 == (byte) 0x90 && sw2 == 0x0)
            result = true;

        return result;
    }

    public boolean getIsExternalReg() {
        return isExternalReg;
    }

    public TPSStatus process(TPSSession session, BeginOp beginMsg) throws EBaseException {
        return TPSStatus.STATUS_NO_ERROR;
    }

    public static void main(String[] args) {
    }

}
