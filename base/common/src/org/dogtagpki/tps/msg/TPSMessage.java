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
package org.dogtagpki.tps.msg;

import java.util.LinkedHashMap;
import java.util.Map;

import org.dogtagpki.tps.main.Util;

import com.netscape.certsrv.apps.CMS;

/**
 * @author Endi S. Dewata <edewata@redhat.com>
 */
public class TPSMessage {

    public enum OpType {
        OP_ENROLL,
        OP_UNBLOCK,
        OP_RESET_PIN,
        OP_RENEW,
        OP_FORMAT,
        OP_UNDEFINED
    }

    public enum MsgType {
        MSG_UNDEFINED,
        MSG_BEGIN_OP,
        MSG_LOGIN_REQUEST,
        MSG_LOGIN_RESPONSE,
        MSG_SECUREID_REQUEST,
        MSG_SECUREID_RESPONSE,
        MSG_ASQ_REQUEST,
        MSG_ASQ_RESPONSE,
        MSG_NEW_PIN_REQUEST,
        MSG_NEW_PIN_RESPONSE,
        MSG_TOKEN_PDU_REQUEST,
        MSG_TOKEN_PDU_RESPONSE,
        MSG_END_OP,
        MSG_STATUS_UPDATE_REQUEST,
        MSG_STATUS_UPDATE_RESPONSE,
        MSG_EXTENDED_LOGIN_REQUEST,
        MSG_EXTENDED_LOGIN_RESPONSE
    }

    //HTTP Protocol values
    public static final String MSG_TYPE_NAME = "msg_type";
    public static final String OPERATION_TYPE_NAME = "operation";
    public static final String EXTENSIONS_NAME = "extensions";

    public static final String INVALID_PWD_NAME = "invalid_pw";
    public static final String BLOCKED_NAME = "blocked";
    public static final String SCREEN_NAME_NAME = "screen_name";
    public static final String PASSWORD_NAME = "password";
    public static final String PIN_REQUIRED_NAME = "pin_required";
    public static final String NEXT_VALUE_NAME = "next_value";
    public static final String VALUE_NAME = "value";
    public static final String PIN_NAME = "pin";
    public static final String QUESTION_NAME = "question";
    public static final String ANSWER_NAME = "answer";
    public static final String MINIMUM_LENGTH_NAME = "minimum_length";
    public static final String MAXIMUM_LENGTH_NAME = "maximum_length";
    public static final String NEW_PIN_NAME = "new_pin";
    public static final String PDU_SIZE_NAME = "pdu_size";
    public static final String PDU_DATA_NAME = "pdu_data";
    public static final String RESULT_NAME = "result";
    public static final String MESSAGE_NAME = "message";
    public static final String STATUS_NAME = "current_state";
    public static final String INFO_NAME = "next_task_name";
    public static final String REQUIRED_PARAMETER_NAME = "required_parameter";
    public static final String PARAMETER_NAME = "parameter";

    private Map<String, String> map = new LinkedHashMap<String, String>();

    public TPSMessage() {
    }

    public TPSMessage(String message) {
        decode(message);
    }

    public TPSMessage(Map<String, String> map) {
        this.map.putAll(map);
    }

    public void put(String key, String value) {
        map.put(key, value);
    }

    public void put(String key, Integer value) {
        map.put(key, value.toString());
    }

    public void put(String key, byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {
            sb.append("%");
            sb.append(String.format("%02X", b));
        }

        map.put(key, sb.toString());
    }

    public String get(String name) {
        String result = null;

        result = map.get(name);

        return result;
    }

    public int getInt(String name) {

        int result = 0;

        String value = map.get(name);

        if (value != null) {
            result = Integer.parseInt(value);
        }

        return result;
    }

    public static Map<String, String> decodeToMap(String message) {

        Map<String, String> msgMap = new LinkedHashMap<String, String>();

        for (String nvp : message.split("&")) {
            String[] s = nvp.split("=");

            String key = s[0];
            String value = s[1];

            // skip message size
            if (key.equals("s"))
                continue;

            msgMap.put(key, value);
        }

        return msgMap;

    }

    public void decode(String message) {

        for (String nvp : message.split("&")) {
            String[] s = nvp.split("=");

            String key = s[0];
            String value = s[1];

            // skip message size
            if (key.equals("s"))
                continue;

            map.put(key, value);
        }
    }

    public String encode() {

        StringBuilder sb = new StringBuilder();

        // encode message type
        String type = map.get("msg_type");
        sb.append("msg_type=" + type);

        // encode other parameters
        for (String key : map.keySet()) {

            if (key.equals("msg_type"))
                continue;

            String value = map.get(key);
            sb.append("&" + key + "=" + value);
        }

        String message = sb.toString();

        // encode message_size
        return "s=" + message.length() + "&" + message;
    }

    public String toString() {
        return map.toString();
    }

    public OpType getOpType() {
        return intToOpType(getInt(OPERATION_TYPE_NAME));
    }

    protected OpType intToOpType(int i) {
        OpType result = OpType.OP_UNDEFINED;

        if (i < 0) {
            return result;
        }

        switch (i) {

        case 0:
            result = OpType.OP_UNDEFINED;
        case 1:
            result = OpType.OP_ENROLL;
            break;
        case 2:
            result = OpType.OP_UNBLOCK;
            break;
        case 3:
            result = OpType.OP_RESET_PIN;
            break;
        case 4:
            result = OpType.OP_RENEW;
            break;
        case 5:
            result = OpType.OP_FORMAT;
            break;
        default:
            result = OpType.OP_UNDEFINED;
            break;

        }

        return result;
    }

    protected int opTypeToInt(OpType op) {
        int result = 0;

        switch (op) {

        case OP_ENROLL:
            result = 1;
            break;
        case OP_UNBLOCK:
            result = 2;
            break;
        case OP_RESET_PIN:
            result = 3;
            break;
        case OP_RENEW:
            result = 4;
            break;
        case OP_FORMAT:
            result = 5;
            break;
        case OP_UNDEFINED:
            result = 0;
        default:
            result = 0;
            break;

        }

        return result;
    }

    protected MsgType intToMsgType(int i) {

        MsgType result = MsgType.MSG_UNDEFINED;

        if (i <= 1) {
            return result;
        }

        switch (i) {
        case 2:
            result = MsgType.MSG_BEGIN_OP;
            break;
        case 3:
            result = MsgType.MSG_LOGIN_REQUEST;
            break;
        case 4:
            result = MsgType.MSG_LOGIN_RESPONSE;
            break;
        case 5:
            result = MsgType.MSG_SECUREID_REQUEST;
            break;
        case 6:
            result = MsgType.MSG_SECUREID_RESPONSE;
            break;
        case 7:
            result = MsgType.MSG_ASQ_REQUEST;
            break;
        case 8:
            result = MsgType.MSG_ASQ_RESPONSE;
            break;
        case 9:
            result = MsgType.MSG_TOKEN_PDU_REQUEST;
            break;
        case 10:
            result = MsgType.MSG_TOKEN_PDU_RESPONSE;
            break;
        case 11:
            result = MsgType.MSG_NEW_PIN_REQUEST;
            break;
        case 12:
            result = MsgType.MSG_NEW_PIN_RESPONSE;
            break;
        case 13:
            result = MsgType.MSG_END_OP;
            break;
        case 14:
            result = MsgType.MSG_STATUS_UPDATE_REQUEST;
            break;
        case 15:
            result = MsgType.MSG_STATUS_UPDATE_RESPONSE;
            break;
        case 16:
            result = MsgType.MSG_EXTENDED_LOGIN_REQUEST;
            break;
        case 17:
            result = MsgType.MSG_EXTENDED_LOGIN_RESPONSE;
            break;

        default:
            result = MsgType.MSG_UNDEFINED;
            break;
        }

        return result;
    }

    protected int msgTypeToInt(MsgType type) {

        int result = 0;

        switch (type) {
        case MSG_BEGIN_OP:
            result = 2;
            break;
        case MSG_LOGIN_REQUEST:
            result = 3;
            break;
        case MSG_LOGIN_RESPONSE:
            result = 4;
            break;
        case MSG_SECUREID_REQUEST:
            result = 5;
            break;
        case MSG_SECUREID_RESPONSE:
            result = 6;
            break;
        case MSG_ASQ_REQUEST:
            result = 7;
            break;
        case MSG_ASQ_RESPONSE:
            result = 8;
            break;
        case MSG_TOKEN_PDU_REQUEST:
            result = 9;
            break;
        case MSG_TOKEN_PDU_RESPONSE:
            result = 10;
            break;
        case MSG_NEW_PIN_REQUEST:
            result = 11;
            break;
        case MSG_NEW_PIN_RESPONSE:
            result = 12;
            break;
        case MSG_END_OP:
            result = 13;
            break;
        case MSG_STATUS_UPDATE_REQUEST:
            result = 14;
            break;
        case MSG_STATUS_UPDATE_RESPONSE:
            result = 15;
            break;
        case MSG_EXTENDED_LOGIN_REQUEST:
            result = 16;
            break;
        case MSG_EXTENDED_LOGIN_RESPONSE:
            result = 17;
            break;

        default:
            result = 0;
            break;
        }

        return result;
    }

    private TPSMessage createMessage() {

        TPSMessage result = null;

        String msg_type = get(MSG_TYPE_NAME);
        String op_type = get(OPERATION_TYPE_NAME);
        String extensions = get(EXTENSIONS_NAME);

        CMS.debug("TPSMessage msg_type: " + msg_type);
        CMS.debug("TPSMessage operation: " + op_type);
        CMS.debug("TPSMessage extensions: " + extensions);

        String decoded = null;
        Map<String, String> extsMap = null;
        if (extensions != null) {
            try {
                decoded = Util.uriDecode(extensions);
            } catch (Exception e) {
                CMS.debug("TPSMessage.createMessage: Util.URIDecode failed: " + e);
                return null;
            }

            System.out.println("decoded extensions : " + decoded);

            extsMap = decodeToMap(decoded);
        }

        int msg_type_int = 0;
        int op_type_int = 0;

        try {
            if (msg_type != null) {
                msg_type_int = Integer.parseInt(msg_type);
            }
            if (op_type != null) {
                op_type_int = Integer.parseInt(op_type);
            }
        } catch (NumberFormatException e) {
            CMS.debug("TPSMessage.createMessage: Error obtaining msg_type or op_type from incoming message.");
        }

        MsgType val = intToMsgType(msg_type_int);
        OpType op_val = intToOpType(op_type_int);

        switch (val) {
        case MSG_BEGIN_OP:
            result = new BeginOp(op_val, extsMap);

            break;
        case MSG_ASQ_REQUEST:
            break;
        case MSG_ASQ_RESPONSE:
            break;
        case MSG_END_OP:
            break;
        case MSG_EXTENDED_LOGIN_REQUEST:
            break;
        case MSG_EXTENDED_LOGIN_RESPONSE:
            break;
        case MSG_LOGIN_REQUEST:
            break;
        case MSG_LOGIN_RESPONSE:
            break;
        case MSG_NEW_PIN_REQUEST:
            break;
        case MSG_NEW_PIN_RESPONSE:
            break;
        case MSG_SECUREID_REQUEST:
            break;
        case MSG_SECUREID_RESPONSE:
            break;
        case MSG_STATUS_UPDATE_REQUEST:
            break;
        case MSG_STATUS_UPDATE_RESPONSE:
            break;
        case MSG_TOKEN_PDU_REQUEST:
            break;
        case MSG_TOKEN_PDU_RESPONSE:
            result = new TokenPDUResponse(encode());
            break;
        case MSG_UNDEFINED:
            return result;
        default:
            return result;

        }

        return result;

    }

    public static TPSMessage createMessage(String message) {

        CMS.debug("TPSMessage.createMessage: message: " + message);

        TPSMessage new_msg = null;
        TPSMessage returnMsg = null;

        new_msg = new TPSMessage(message);

        returnMsg = new_msg.createMessage();

        return returnMsg;
    }

    public MsgType getType() {

        int res = getInt(MSG_TYPE_NAME);
        return intToMsgType(res);
    }

    public static void main(String[] args) {
        String encoded = "s=204&msg_type=2&operation=5&extensions=tokenType%3DuserKey%26clientVersion%3DESC+1%2E0%2E1%26tokenATR%3D3BFF1400FF8131FE458025A00000005657534336353003003B%26statusUpdate%3Dtrue%26extendedLoginRequest%3Dtrue%26";
        BeginOp testMessage = (BeginOp) TPSMessage.createMessage(encoded);
        System.out.println("Encoded msg: " + testMessage.encode());
        System.out.println("msg Extensions: " + testMessage.GetExtensions());

    }

}
