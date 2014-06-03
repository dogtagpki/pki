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



public class EndOpMsg extends TPSMessage {

    public enum TPSStatus {
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


    public static final int  RESULT_GOOD = 0;
    public static final int  RESULT_ERROR = 1;


    public EndOpMsg(OpType theOp, int result, TPSStatus message) {
        put(MSG_TYPE_NAME, msgTypeToInt(MsgType.MSG_END_OP));
        put(OPERATION_TYPE_NAME, opTypeToInt(theOp));
        put(RESULT_NAME, result);
        put(MESSAGE_NAME, statusToInt(message));
    }

    public static int statusToInt(TPSStatus status) {

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

    public static void main(String[] args) {

        EndOpMsg end_msg = new EndOpMsg(OpType.OP_FORMAT,0,TPSStatus.STATUS_NO_ERROR);
        System.out.println(end_msg.encode());


    }

}
