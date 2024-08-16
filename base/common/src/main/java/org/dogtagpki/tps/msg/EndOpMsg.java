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
        STATUS_NO_ERROR(0),
        STATUS_ERROR_SNAC(1),
        STATUS_ERROR_SEC_INIT_UPDATE(2),
        STATUS_ERROR_CREATE_CARDMGR(3),
        STATUS_ERROR_MAC_RESET_PIN_PDU(4),
        STATUS_ERROR_MAC_CERT_PDU(5),
        STATUS_ERROR_MAC_LIFECYCLE_PDU(6),
        STATUS_ERROR_MAC_ENROLL_PDU(7),
        STATUS_ERROR_CANNOT_PERFORM_OPERATION(8),
        STATUS_ERROR_BAD_STATUS(9),
        STATUS_ERROR_CA_RESPONSE(10),
        STATUS_ERROR_READ_BUFFER_OVERFLOW(11),
        STATUS_ERROR_TOKEN_RESET_PIN_FAILED(12),
        STATUS_ERROR_CONNECTION(13),
        STATUS_ERROR_LOGIN(14),
        STATUS_ERROR_DB(15),
        STATUS_ERROR_UNKNOWN_TOKEN(16),
        STATUS_ERROR_SECURE_CHANNEL(17),
        STATUS_ERROR_MISCONFIGURATION(18),
        STATUS_ERROR_UPGRADE_APPLET(19),
        STATUS_ERROR_KEY_CHANGE_OVER(20),
        STATUS_ERROR_EXTERNAL_AUTH(21),
        STATUS_ERROR_MAPPING_RESOLVER_FAILED(22), // was STATUS_ERROR_DEFAULT_TOKENTYPE_NOT_FOUND
        STATUS_ERROR_MAPPING_RESOLVER_PARAMS_NOT_FOUND(23), // was STATUS_ERROR_DEFAULT_TOKENTYPE_PARAMS_NOT_FOUND
        STATUS_ERROR_PUBLISH(24),
        STATUS_ERROR_LDAP_CONN(25),
        STATUS_ERROR_DISABLED_TOKEN(26),
        STATUS_ERROR_NOT_PIN_RESETABLE(27),
        STATUS_ERROR_CONN_LOST(28),
        STATUS_ERROR_CREATE_TUS_TOKEN_ENTRY(29),
        STATUS_ERROR_NO_SUCH_TOKEN_STATE(30),
        STATUS_ERROR_NO_SUCH_LOST_REASON(31),
        STATUS_ERROR_UNUSABLE_TOKEN_KEYCOMPROMISE(32),
        STATUS_ERROR_INACTIVE_TOKEN_NOT_FOUND(33),
        STATUS_ERROR_HAS_AT_LEAST_ONE_ACTIVE_TOKEN(34),
        STATUS_ERROR_TOKEN_TERMINATED(35),
        STATUS_RECOVERY_IS_PROCESSED(36),
        STATUS_ERROR_RECOVERY_FAILED(37),
        STATUS_ERROR_RENEWAL_FAILED(37),
        STATUS_ERROR_NO_OPERATION_ON_LOST_TOKEN(38),
        STATUS_ERROR_KEY_ARCHIVE_OFF(39),
        STATUS_ERROR_NO_TKS_CONNID(40),
        STATUS_ERROR_UPDATE_TOKENDB_FAILED(41),
        STATUS_ERROR_REVOKE_CERTIFICATES_FAILED(42),
        STATUS_ERROR_NOT_TOKEN_OWNER(43),
        STATUS_RENEWAL_IS_PROCESSED(44),
        STATUS_ERROR_CANNOT_ESTABLISH_COMMUNICATION(45),
        STATUS_ERROR_SYMKEY_256_UPGRADE(46); // ** G&D 256 Key Rollover Support **

        private TPSStatus(int code) {
            this.code = code;
        }

        public final int code;
    }

    public static final int  RESULT_GOOD = 0;
    public static final int  RESULT_ERROR = 1;


    public EndOpMsg(OpType theOp, int result, TPSStatus message) {
        put(MSG_TYPE_NAME, msgTypeToInt(MsgType.MSG_END_OP));
        put(OPERATION_TYPE_NAME, opTypeToInt(theOp));
        put(RESULT_NAME, result);
        put(MESSAGE_NAME, message.code);
    }

    public static void main(String[] args) {

        EndOpMsg end_msg = new EndOpMsg(OpType.OP_FORMAT,0,TPSStatus.STATUS_NO_ERROR);
        System.out.println(end_msg.encode());


    }

}
