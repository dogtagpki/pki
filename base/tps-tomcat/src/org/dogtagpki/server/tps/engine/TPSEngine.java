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

import org.dogtagpki.server.tps.cms.KRARemoteRequestHandler;
import org.dogtagpki.server.tps.cms.KRAServerSideKeyGenResponse;
import org.dogtagpki.server.tps.cms.TKSComputeSessionKeyResponse;
import org.dogtagpki.server.tps.cms.TKSCreateKeySetDataResponse;
import org.dogtagpki.server.tps.cms.TKSRemoteRequestHandler;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class TPSEngine {

    public enum RA_Algs {
        ALG_RSA,
        ALG_RSA_CRT,
        ALG_DSA,
        ALG_EC_F2M,
        ALG_EC_FP
    };

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
    public static final String CFG_AUDIT_SELECTED_EVENTS = "logging.audit.selected.events";
    public static final String CFG_AUDIT_NONSELECTABLE_EVENTS = "logging.audit.nonselectable.events";
    public static final String CFG_AUDIT_SELECTABLE_EVENTS = "logging.audit.selectable.events";
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
    public static final String CFG_AUTHS_ENABLE = "auth.enable";
    public static final String CFG_PROFILE_MAPPING_ORDER = "mapping.order";
    public static final String CFG_ALLOW_UNKNOWN_TOKEN = "allowUnkonwnToken";
    public static final String CFG_ALLOW_NO_APPLET = "update.applet.emptyToken.enable";
    public static final String CFG_APPLET_UPDATE_REQUIRED_VERSION = "update.applet.requiredVersion";
    public static final String CFG_APPLET_DIRECTORY = "update.applet.directory";
    public static final String CFG_APPLET_EXTENSION = "general.applet_ext";

    public static final String CFG_CHANNEL_BLOCK_SIZE = "channel.blockSize";
    public static final String CFG_CHANNEL_INSTANCE_SIZE = "channel.instanceSize";
    public static final String CFG_CHANNEL_DEFKEY_VERSION = "channel.defKeyVersion";
    public static final String CFG_CHANNEL_APPLET_MEMORY_SIZE = "channel.appletMemorySize";
    public static final String CFG_CHANNEL_DEFKEY_INDEX = "channel.defKeyIndex";
    public static final String CFG_ISSUER_INFO_ENABLE = "issuerinfo.enable";
    public static final String CFG_ISSUER_INFO_VALUE = "issuerinfo.value";
    public static final String CFG_UPDATE_APPLET_ENCRYPTION = "update.applet.encryption";
    public static final String CFG_UPDATE_APPLET_ENABLE = "update.applet.enable";
    public static final String CFG_SYMM_KEY_UPGRADE_ENABLED = "update.symmetricKeys.enable";

    /* default values */
    public static final String CFG_DEF_CARDMGR_INSTANCE_AID = "A0000000030000";
    public static final String CFG_DEF_NETKEY_INSTANCE_AID = "627601FF000000";
    public static final String CFG_DEF_NETKEY_FILE_AID = "627601FF0000";
    public static final String CFG_DEF_NETKEY_OLD_INSTANCE_AID = "A00000000101";
    public static final String CFG_DEF_NETKEY_OLD_FILE_AID = "A000000001";
    public static final String CFG_DEF_APPLET_SO_PIN = "000000000000";
    public static final String CFG_ENABLED = "Enabled";

    public static final int CFG_CHANNEL_DEF_BLOCK_SIZE = 242;
    public static final int CFG_CHANNEL_DEF_INSTANCE_SIZE = 18000;
    public static final int CFG_CHANNEL_DEF_APPLET_MEMORY_SIZE = 5000;

    /* token enrollment values */
    public static final String CFG_KEYGEN_ENCRYPTION = "keyGen.encryption";
    public static final String CFG_KEYGEN_KEYTYPE_NUM = "keyGen.keyType.num";
    public static final String CFG_KEYGEN_KEYTYPE_VALUE = "keyGen.keyType.value";
    public static final String CFG_SERVER_KEYGEN_ENABLE = "serverKeygen.enable";
    public static final String CFG_SERVER_KEY_ARCHIVAL = "serverKeygen.archive";
    public static final String CFG_DRM_CONNECTOR = "serverKeygen.drm.conn";

    /* token renewal values */
    public static final String CFG_RENEW_KEYTYPE_NUM = "renewal.keyType.num";
    public static final String CFG_RENEW_KEYTYPE_VALUE = "renewal.keyType.value";

    /* External reg values */

    public static final String CFG_EXTERNAL_REG = "externalReg";

    /* misc values */

    public static final String OP_FORMAT_PREFIX = "op.format";
    public static final String CFG_PROFILE_RESOLVER = "tokenProfileResolver";
    public static final String CFG_DEF_FORMAT_PROFILE_RESOLVER = "formatMappingResolver";
    public static final String CFG_DEF_ENROLL_PROFILE_RESOLVER = "enrollMappingResolver";
    public static final String CFG_DEF_PIN_RESET_PROFILE_RESOLVER = "pinResetMappingResolver";
    public static final String OP_ENROLL_PREFIX = "op.enroll";
    public static final String OP_PIN_RESET_PREFIX = "op.pinReset";
    public static final String CFG_PIN_RESET_ENABLE = "pinReset.enable";
    public static final String CFG_PIN_RESET_MIN_LEN = "pinReset.pin.minLen";
    public static final String CFG_PIN_RESET_MAX_LEN = "pinReset.pin.maxLen";
    public static final String CFG_PIN_RESET_MAX_RETRIES = "pinReset.pin.maxRetries";
    public static final String CFG_PIN_RESET_STRING = "create_pin.string";
    public static final String ENROLL_OP = "enroll";
    public static final String FORMAT_OP = "format";

    public static String CFG_OVERWRITE = "overwrite";
    public static String PIN_RESET_OP = "pin_reset";

    public void init() {
        //ToDo
    }

    public TPSEngine() {
    }

    public int initialize(String cfg_path) {

        int rc = -1;

        return rc;
    }

    public TKSComputeSessionKeyResponse computeSessionKey(TPSBuffer cuid,
            TPSBuffer keyInfo,
            TPSBuffer card_challenge,
            TPSBuffer host_challenge,
            TPSBuffer card_cryptogram,
            String connId,
            String tokenType) throws TPSException {

        if (cuid == null || keyInfo == null || card_challenge == null || host_challenge == null
                || card_cryptogram == null || connId == null || tokenType == null) {

            throw new TPSException("TPSEngine.computeSessionKey: Invalid input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

        }

        CMS.debug("TPSEngine.computeSessionKey");

        TKSRemoteRequestHandler tks = null;

        TKSComputeSessionKeyResponse resp = null;
        try {
            tks = new TKSRemoteRequestHandler(connId);
            resp = tks.computeSessionKey(cuid, keyInfo, card_challenge, card_cryptogram, host_challenge, tokenType);
        } catch (EBaseException e) {
            throw new TPSException("TPSEngine.computeSessionKey: Error computing session key!" + e,
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        int status = resp.getStatus();
        if (status != 0) {
            CMS.debug("TPSEngine.computeSessionKey: Non zero status result: " + status);
            throw new TPSException("TPSEngine.computeSessionKey: invalid returned status: " + status);

        }

        return resp;

    }

    public TPSBuffer createKeySetData(TPSBuffer newMasterVersion, TPSBuffer oldVersion, TPSBuffer cuid, String connId)
            throws TPSException {
        CMS.debug("TPSEngine.createKeySetData. entering...");

        if (newMasterVersion == null || oldVersion == null || cuid == null || connId == null) {
            throw new TPSException("TPSEngine.createKeySetData: Invalid input data",
                    TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

        TKSRemoteRequestHandler tks = null;

        TKSCreateKeySetDataResponse resp = null;

        try {
            tks = new TKSRemoteRequestHandler(connId);
            resp = tks.createKeySetData(newMasterVersion, oldVersion, cuid);
        } catch (EBaseException e) {

            throw new TPSException("TPSEngine.createKeySetData, failure to get key set data from TKS",
                    TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

        int status = resp.getStatus();
        if (status != 0) {
            CMS.debug("TPSEngine.createKeySetData: Non zero status result: " + status);
            throw new TPSException("TPSEngine.computeSessionKey: invalid returned status: " + status,
                    TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);

        }

        TPSBuffer keySetData = resp.getKeySetData();

        if (keySetData == null) {
            CMS.debug("TPSEngine.createKeySetData: No valid key set data returned.");
            throw new TPSException("TPSEngine.createKeySetData: No valid key set data returned.",
                    TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);

        }

        return keySetData;
    }

    public static void main(String[] args) {

    }

    public boolean raForceTokenFormat(String cuid) {
        // TODO Auto-generated method stub
        return false;
    }

    public boolean isAlgorithmECC(int algorithm) {

        RA_Algs algEnum = intToRAAlgs(algorithm);

        boolean isECC = false;

        if (algEnum == RA_Algs.ALG_EC_F2M || algEnum == RA_Algs.ALG_EC_FP) {
            isECC = true;
        }

        CMS.debug("TPSEngine.isAlgorithmECC: result: " + isECC);
        return isECC;

    }

    public static RA_Algs intToRAAlgs(int alg) {

        RA_Algs def = RA_Algs.ALG_RSA;

        switch (alg) {

        case 1:
            return RA_Algs.ALG_RSA;

        case 2:
            return RA_Algs.ALG_RSA_CRT;
        case 3:
            return RA_Algs.ALG_DSA;
        case 4:
            return RA_Algs.ALG_EC_F2M;
        case 5:
            return RA_Algs.ALG_EC_FP;

        default:
            return def;

        }

    }

    public KRAServerSideKeyGenResponse serverSideKeyGen(int keySize, String cuid, String userid, String drmConnId,
            TPSBuffer wrappedDesKey,
            boolean archive,
            boolean isECC) throws TPSException {

        CMS.debug("TPSEngine.serverSideKeyGen entering... keySize: " + keySize + " cuid: " + cuid + " userid: "
                + userid + " drConnId: " + drmConnId + " wrappedDesKey: " + wrappedDesKey + " archive: " + archive
                + " isECC: " + isECC);

        if (cuid == null || userid == null || drmConnId == null || wrappedDesKey == null) {
            throw new TPSException("TPSEngine.serverSideKeyGen: Invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        KRARemoteRequestHandler kra = null;
        KRAServerSideKeyGenResponse resp = null;

        try {
            kra = new KRARemoteRequestHandler(drmConnId);

            resp = kra.serverSideKeyGen(isECC, keySize, cuid, userid,
                    Util.specialURLEncode(wrappedDesKey), archive);

        } catch (EBaseException e) {
            throw new TPSException("TPSEngine.serverSideKeyGen: Problem creating KRARemoteRequestHandler! "
                    + e.toString());
        }

        int status = resp.getStatus();

        if (status != 0) {
            throw new TPSException("TPSEngine.serverSideKeyGen: Bad status from server: " + status,
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        if (resp.getPublicKey() == null) {
            throw new TPSException("TPSEngine.serverSideKeyGen: invalid public key from server! ",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        if (resp.getWrappedPrivKey() == null) {
            throw new TPSException("TPSEngine.serverSideKeyGen: invalid private key from server! ",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        if (resp.getIVParam() == null) {
            throw new TPSException("TPSEngine.serverSideKeyGen: invalid iv vector from server!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        //We return this resonse we know that all the data is present and can be accessed
        return resp;

    }

}
