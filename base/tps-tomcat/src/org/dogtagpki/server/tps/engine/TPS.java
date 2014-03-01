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
package org.dogtagpki.server.tps.engine;

public class TPS {

    public static final String TKS_RESPONSE_STATUS = "status";
    public static final String TKS_RESPONSE_SessionKey = "sessionKey";
    public static final String TKS_RESPONSE_EncSessionKey = "encSessionKey";
    public static final String TKS_RESPONSE_KEK_DesKey = "kek_wrapped_desKey";
    public static final String TKS_RESPONSE_DRM_Trans_DesKey = "drm_trans_wrapped_desKey";
    public static final String TKS_RESPONSE_HostCryptogram = "hostCryptogram";

    public static final String CFG_DEBUG_ENABLE = "logging.debug.enable";
    public static final String CFG_DEBUG_FILENAME = "logging.debug.filename";
    public static final String CFG_DEBUG_LEVEL = "logging.debug.level";
    public static final String CFG_AUDIT_ENABLE = "logging.audit.enable";
    public static final String CFG_AUDIT_FILENAME = "logging.audit.filename";
    public static final String CFG_SIGNED_AUDIT_FILENAME = "logging.audit.signedAuditFilename";
    public static final String CFG_AUDIT_LEVEL = "logging.audit.level";
    public static final String CFG_AUDIT_SIGNED = "logging.audit.logSigning";
    public static final String CFG_AUDIT_SIGNING_CERT_NICK = "logging.audit.signedAuditCertNickname";
    public static final String CFG_ERROR_ENABLE = "logging.error.enable";
    public static final String CFG_ERROR_FILENAME = "logging.error.filename";
    public static final String CFG_ERROR_LEVEL = "logging.error.level";
    public static final String CFG_SELFTEST_ENABLE = "selftests.container.logger.enable";
    public static final String CFG_SELFTEST_FILENAME = "selftests.container.logger.fileName";
    public static final String CFG_SELFTEST_LEVEL = "selftests.container.logger.level";
    public static final String CFG_CHANNEL_SEC_LEVEL = "channel.securityLevel";
    public static final String CFG_CHANNEL_ENCRYPTION = "channel.encryption";
    public static final String CFG_APPLET_CARDMGR_INSTANCE_AID = "applet.aid.cardmgr_instance";
    public static final String CFG_APPLET_NETKEY_INSTANCE_AID = "applet.aid.netkey_instance";
    public static final String CFG_APPLET_NETKEY_FILE_AID = "applet.aid.netkey_file";
    public static final String CFG_APPLET_NETKEY_OLD_INSTANCE_AID = "applet.aid.netkey_old_instance";
    public static final String CFG_APPLET_NETKEY_OLD_FILE_AID = "applet.aid.netkey_old_file";
    public static final String CFG_APPLET_SO_PIN = "applet.so_pin";
    public static final String CFG_APPLET_DELETE_NETKEY_OLD = "applet.delete_old";
    public static final String CFG_AUDIT_SELECTED_EVENTS="logging.audit.selected.events";
    public static final String CFG_AUDIT_NONSELECTABLE_EVENTS="logging.audit.nonselectable.events";
    public static final String CFG_AUDIT_SELECTABLE_EVENTS="logging.audit.selectable.events";
    public static final String CFG_AUDIT_BUFFER_SIZE = "logging.audit.buffer.size";
    public static final String CFG_AUDIT_FLUSH_INTERVAL = "logging.audit.flush.interval";
    public static final String CFG_AUDIT_FILE_TYPE = "logging.audit.file.type";
    public static final String CFG_DEBUG_FILE_TYPE = "logging.debug.file.type";
    public static final String CFG_ERROR_FILE_TYPE = "logging.error.file.type";
    public static final String CFG_SELFTEST_FILE_TYPE = "selftests.container.logger.file.type";
    public static final String CFG_AUDIT_PREFIX = "logging.audit";
    public static final String CFG_ERROR_PREFIX = "logging.error";
    public static final String CFG_DEBUG_PREFIX = "logging.debug";
    public static final String CFG_SELFTEST_PREFIX = "selftests.container.logger";
    public static final String CFG_TOKENDB_ALLOWED_TRANSITIONS = "tokendb.allowedTransitions";
    public static final String CFG_OPERATIONS_ALLOWED_TRANSITIONS = "tps.operations.allowedTransitions";

    public static final String CFG_PRINTBUF_FULL = "tps.printBufFull";
    public static final String CFG_RECV_BUF_SIZE = "tps.recvBufSize";
    public static final String CFG_AUTHS_ENABLE="auth.enable";
    public static final String CFG_PROFILE_MAPPING_ORDER="mapping.order";

    /* default values */
    public static final String CFG_DEF_CARDMGR_INSTANCE_AID = "A0000000030000";
    public static final String CFG_DEF_NETKEY_INSTANCE_AID = "627601FF000000";
    public static final String CFG_DEF_NETKEY_FILE_AID = "627601FF0000";
    public static final String CFG_DEF_NETKEY_OLD_INSTANCE_AID = "A00000000101";
    public static final String CFG_DEF_NETKEY_OLD_FILE_AID = "A000000001";
    public static final String CFG_DEF_APPLET_SO_PIN = "000000000000";

    /* External reg values */

    public static final String CFG_EXTERNAL_REG = "externalReg";

    /* misc values */

    public static final String OP_FORMAT_PREFEX = "op.format";



    public TPS() {
    }

    public int initialize(String cfg_path) {

        int rc = -1;

        return rc;
    }

    public static void main(String[] args) {

    }

}
