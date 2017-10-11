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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging;

/**
 * The log event object that carries message detail of a log event
 * that goes into the Transaction log. Note that the name of this
 * class "AuditEvent" is legacy and has nothing to do with the signed
 * audit log events, whcih are represented by SignedAuditEvent.
 *
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 * @see com.netscape.certsrv.logging.LogResources
 */
public class AuditEvent extends LogEvent {

    public final static String AUDIT_LOG_STARTUP =
            "LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP_2";
    public final static String AUDIT_LOG_SHUTDOWN =
            "LOGGING_SIGNED_AUDIT_AUDIT_LOG_SHUTDOWN_2";
    public final static String CIMC_CERT_VERIFICATION =
            "LOGGING_SIGNED_AUDIT_CIMC_CERT_VERIFICATION_3";
    public final static String CONFIG_CERT_POLICY =
            "LOGGING_SIGNED_AUDIT_CONFIG_CERT_POLICY_3";
    public final static String CONFIG_CERT_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_CERT_PROFILE_3";
    public final static String CONFIG_CRL_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_CRL_PROFILE_3";
    public final static String CONFIG_OCSP_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_OCSP_PROFILE_3";
    public final static String CONFIG_AUTH =
            "LOGGING_SIGNED_AUDIT_CONFIG_AUTH_3";
    public final static String CONFIG_ACL =
            "LOGGING_SIGNED_AUDIT_CONFIG_ACL_3";
    public final static String CONFIG_ENCRYPTION =
            "LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION_3";
    public final static String CONFIG_DRM =
            "LOGGING_SIGNED_AUDIT_CONFIG_DRM_3";
    public final static String SELFTESTS_EXECUTION =
            "LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION_2";
    public final static String AUDIT_LOG_DELETE =
            "LOGGING_SIGNED_AUDIT_LOG_DELETE_3";
    public final static String LOG_PATH_CHANGE =
            "LOGGING_SIGNED_AUDIT_LOG_PATH_CHANGE_4";

    public final static String KEY_RECOVERY_AGENT_LOGIN =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN_4";
    public final static String KEY_GEN_ASYMMETRIC =
            "LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC_3";

    public final static String NON_PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST_5";
    public final static String PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST_5";
    public final static String INTER_BOUNDARY =
            "LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS_5";
    public final static String CERT_PROFILE_APPROVAL =
            "LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL_4";
    public final static String PROOF_OF_POSSESSION =
            "LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION_3";
    public final static String CMC_PROOF_OF_IDENTIFICATION =
            "LOGGING_SIGNED_AUDIT_CMC_PROOF_OF_IDENTIFICATION_3";
    public final static String CMC_ID_POP_LINK_WITNESS =
            "LOGGING_SIGNED_AUDIT_CMC_ID_POP_LINK_WITNESS_3";

    public final static String CRL_RETRIEVAL =
            "LOGGING_SIGNED_AUDIT_CRL_RETRIEVAL_3";
    public final static String CRL_VALIDATION =
            "LOGGING_SIGNED_AUDIT_CRL_VALIDATION_2";
    public final static String CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS =
            "LOGGING_SIGNED_AUDIT_CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS_5";
    public final static String CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE =
            "LOGGING_SIGNED_AUDIT_CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE_6";

    public final static String COMPUTE_RANDOM_DATA_REQUEST =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_2";
    public final static String COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS_3";
    public final static String COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE_4";
    public final static String COMPUTE_SESSION_KEY_REQUEST =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_4"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.
    public final static String COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS_13"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.  Also added TKSKeyset, KeyInfo_KeyVersion, NistSP800_108KdfOnKeyVersion, NistSP800_108KdfUseCuidAsKdd.
    public final static String COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE_14"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.  Also added TKSKeyset, KeyInfo_KeyVersion, NistSP800_108KdfOnKeyVersion, NistSP800_108KdfUseCuidAsKdd.
    public final static String DIVERSIFY_KEY_REQUEST =
            "LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_6"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.
    public final static String DIVERSIFY_KEY_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_SUCCESS_12"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.  Also added TKSKeyset, OldKeyInfo_KeyVersion, NewKeyInfo_KeyVersion, NistSP800_108KdfOnKeyVersion, NistSP800_108KdfUseCuidAsKdd.
    public final static String DIVERSIFY_KEY_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_DIVERSIFY_KEY_REQUEST_PROCESSED_FAILURE_13"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.  Also added TKSKeyset, OldKeyInfo_KeyVersion, NewKeyInfo_KeyVersion, NistSP800_108KdfOnKeyVersion, NistSP800_108KdfUseCuidAsKdd.
    public final static String ENCRYPT_DATA_REQUEST =
            "LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_5"; // AC: KDF SPEC CHANGE:  Need to log both KDD and CUID.
    public final static String ENCRYPT_DATA_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_SUCCESS_12";
    public final static String ENCRYPT_DATA_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_ENCRYPT_DATA_REQUEST_PROCESSED_FAILURE_13";

    public final static String SECURITY_DOMAIN_UPDATE =
            "LOGGING_SIGNED_AUDIT_SECURITY_DOMAIN_UPDATE_1";
    public final static String CONFIG_SERIAL_NUMBER =
            "LOGGING_SIGNED_AUDIT_CONFIG_SERIAL_NUMBER_1";

    public final static String TOKEN_CERT_ENROLLMENT =
            "LOGGING_SIGNED_AUDIT_TOKEN_CERT_ENROLLMENT_9";
    public final static String TOKEN_CERT_RENEWAL =
            "LOGGING_SIGNED_AUDIT_TOKEN_CERT_RENEWAL_9";
    public final static String TOKEN_CERT_RETRIEVAL =
            "LOGGING_SIGNED_AUDIT_TOKEN_CERT_RETRIEVAL_9";
    public final static String TOKEN_KEY_RECOVERY =
            "LOGGING_SIGNED_AUDIT_TOKEN_KEY_RECOVERY_10";
    public final static String TOKEN_CERT_STATUS_CHANGE_REQUEST =
            "LOGGING_SIGNED_AUDIT_TOKEN_CERT_STATUS_CHANGE_REQUEST_10";
    public final static String TOKEN_PIN_RESET_SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_PIN_RESET_SUCCESS_6";
    public final static String TOKEN_PIN_RESET_FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_PIN_RESET_FAILURE_6";
    public final static String TOKEN_OP_REQUEST =
            "LOGGING_SIGNED_AUDIT_TOKEN_OP_REQUEST_6";
    public final static String TOKEN_FORMAT_SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_FORMAT_SUCCESS_9";
    public final static String TOKEN_FORMAT_FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_FORMAT_FAILURE_9";
    public final static String TOKEN_APPLET_UPGRADE_SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_APPLET_UPGRADE_SUCCESS_9";
    public final static String TOKEN_APPLET_UPGRADE_FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_APPLET_UPGRADE_FAILURE_9";
    public final static String TOKEN_KEY_CHANGEOVER_REQUIRED =
            "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_REQUIRED_10";
    public final static String TOKEN_KEY_CHANGEOVER_SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_SUCCESS_10";
    public final static String TOKEN_KEY_CHANGEOVER_FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_FAILURE_10";
    public final static String TOKEN_AUTH_FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_AUTH_FAILURE_9";
    public final static String TOKEN_AUTH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_AUTH_SUCCESS_9";
    public final static String CONFIG_TOKEN_GENERAL =
            "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_GENERAL_5";
    public final static String CONFIG_TOKEN_PROFILE =
            "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_PROFILE_6";
    public final static String CONFIG_TOKEN_MAPPING_RESOLVER =
            "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_MAPPING_RESOLVER_6";
    public final static String CONFIG_TOKEN_AUTHENTICATOR =
            "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_AUTHENTICATOR_6";
    public final static String CONFIG_TOKEN_CONNECTOR =
            "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_CONNECTOR_6";
    public final static String CONFIG_TOKEN_RECORD =
            "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_RECORD_6";
    public final static String TOKEN_STATE_CHANGE =
            "LOGGING_SIGNED_AUDIT_TOKEN_STATE_CHANGE_8";
    public final static String AUTHORITY_CONFIG =
            "LOGGING_SIGNED_AUDIT_AUTHORITY_CONFIG_3";

    public final static String AUDIT_LOG_SIGNING =
            "LOGGING_SIGNED_AUDIT_SIGNING_3";

    private static final long serialVersionUID = -844306657733902324L;

    public AuditEvent() {
    }

    /**
     * Constructs a message event
     * <P>
     *
     * @param msgFormat the message string
     */
    public AuditEvent(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a message with a parameter. For example,
     *
     * <PRE>
     * new AuditEvent(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     *
     * @param msgFormat details in message string format
     * @param param message string parameter
     */
    public AuditEvent(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a message from an exception. It can be used to carry
     * a system exception that may contain information about
     * the context. For example,
     *
     * <PRE>
     *         try {
     *          ...
     *         } catch (IOExeption e) {
     *              logHandler.log(new AuditEvent("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param exception system exception
     */
    public AuditEvent(String msgFormat, Exception exception) {
        super(msgFormat, exception);
    }

    /**
     * Constructs a message from a base exception. This will use the msgFormat
     * from the exception itself.
     *
     * <PRE>
     *         try {
     *          ...
     *         } catch (Exception e) {
     *              logHandler.log(new AuditEvent(e));
     *      }
     * </PRE>
     * <P>
     *
     * @param e CMS exception
     */
    public AuditEvent(Exception e) {
        super(e);
    }

    /**
     * Constructs a message event with a list of parameters
     * that will be substituted into the message format.
     * <P>
     *
     * @param msgFormat message string format
     * @param params list of message format parameters
     */
    public AuditEvent(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }
}
