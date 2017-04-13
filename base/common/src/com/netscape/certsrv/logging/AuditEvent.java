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

import java.text.MessageFormat;
import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MessageFormatter;

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
public class AuditEvent implements IBundleLogEvent {

    public final static String AUDIT_LOG_STARTUP =
            "LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP_2";
    public final static String AUDIT_LOG_SHUTDOWN =
            "LOGGING_SIGNED_AUDIT_AUDIT_LOG_SHUTDOWN_2";
    public final static String CIMC_CERT_VERIFICATION =
            "LOGGING_SIGNED_AUDIT_CIMC_CERT_VERIFICATION_3";
    public final static String ROLE_ASSUME =
            "LOGGING_SIGNED_AUDIT_ROLE_ASSUME_3";
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
    public final static String CONFIG_ROLE =
            "LOGGING_SIGNED_AUDIT_CONFIG_ROLE_3";
    public final static String CONFIG_ACL =
            "LOGGING_SIGNED_AUDIT_CONFIG_ACL_3";
    public final static String CONFIG_SIGNED_AUDIT =
            "LOGGING_SIGNED_AUDIT_CONFIG_SIGNED_AUDIT_3";
    public final static String CONFIG_ENCRYPTION =
            "LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION_3";
    public final static String CONFIG_TRUSTED_PUBLIC_KEY =
            "LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY_3";
    public final static String CONFIG_DRM =
            "LOGGING_SIGNED_AUDIT_CONFIG_DRM_3";
    public final static String SELFTESTS_EXECUTION =
            "LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION_2";
    public final static String AUDIT_LOG_DELETE =
            "LOGGING_SIGNED_AUDIT_LOG_DELETE_3";
    public final static String LOG_PATH_CHANGE =
            "LOGGING_SIGNED_AUDIT_LOG_PATH_CHANGE_4";

    public final static String PRIVATE_KEY_ARCHIVE_REQUEST =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_4";
    public final static String PRIVATE_KEY_ARCHIVE_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_ARCHIVE_REQUEST_PROCESSED_3";
    public final static String PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_SUCCESS_4";
    public final static String PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_PRIVATE_KEY_EXPORT_REQUEST_PROCESSED_FAILURE_4";
    public final static String SERVER_SIDE_KEYGEN_REQUEST =
            "LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_3";
    public final static String SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_SUCCESS_4";
    public final static String SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_FAILURE_3";
    public final static String KEY_RECOVERY_REQUEST =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_4";
    public final static String KEY_RECOVERY_REQUEST_ASYNC =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_ASYNC_4";
    public final static String KEY_RECOVERY_AGENT_LOGIN =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_AGENT_LOGIN_4";
    public final static String KEY_RECOVERY_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_PROCESSED_4";
    public final static String KEY_RECOVERY_REQUEST_PROCESSED_ASYNC =
            "LOGGING_SIGNED_AUDIT_KEY_RECOVERY_REQUEST_PROCESSED_ASYNC_4";
    public final static String KEY_GEN_ASYMMETRIC =
            "LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC_3";

    public final static String NON_PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST_5";
    public final static String PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST_5";
    public final static String CERT_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";
    public final static String CERT_STATUS_CHANGE_REQUEST =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_5";
    public final static String CERT_STATUS_CHANGE_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED_7";

    public final static String AUTHZ_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS_4";
    public final static String AUTHZ_SUCCESS_INFO =
            "LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS_5";
    public final static String AUTHZ_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTHZ_FAIL_4";
    public final static String AUTHZ_FAIL_INFO =
            "LOGGING_SIGNED_AUDIT_AUTHZ_FAIL_5";
    public final static String INTER_BOUNDARY =
            "LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS_5";
    public final static String AUTH_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTH_FAIL_4";
    public final static String AUTH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTH_SUCCESS_3";
    public final static String CERT_PROFILE_APPROVAL =
            "LOGGING_SIGNED_AUDIT_CERT_PROFILE_APPROVAL_4";
    public final static String PROOF_OF_POSSESSION =
            "LOGGING_SIGNED_AUDIT_PROOF_OF_POSSESSION_2";

    public final static String CRL_RETRIEVAL =
            "LOGGING_SIGNED_AUDIT_CRL_RETRIEVAL_3";
    public final static String CRL_VALIDATION =
            "LOGGING_SIGNED_AUDIT_CRL_VALIDATION_2";
    public final static String OCSP_ADD_CA_REQUEST =
            "LOGGING_SIGNED_AUDIT_OCSP_ADD_CA_REQUEST_3";
    public final static String OCSP_ADD_CA_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_OCSP_ADD_CA_REQUEST_PROCESSED_3";
    public final static String OCSP_REMOVE_CA_REQUEST =
            "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_3";
    public final static String OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS_3";
    public final static String OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE_3";
    public final static String CMC_SIGNED_REQUEST_SIG_VERIFY =
            "LOGGING_SIGNED_AUDIT_CMC_SIGNED_REQUEST_SIG_VERIFY_5";

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

    public final static String SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED_6";
    public static final String SECURITY_DATA_ARCHIVAL_REQUEST =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_ARCHIVAL_REQUEST_4";
    public final static String SECURITY_DATA_RECOVERY_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_PROCESSED_5";
    public static final String SECURITY_DATA_RECOVERY_REQUEST =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_4";
    public static final String SECURITY_DATA_RECOVERY_REQUEST_STATE_CHANGE =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RECOVERY_REQUEST_STATE_CHANGE_4";
    public final static String SECURITY_DATA_RETRIEVE_KEY =
            "LOGGING_SIGNED_AUDIT_SECURITY_DATA_RETRIEVE_KEY_5";
    public final static String KEY_STATUS_CHANGE =
            "LOGGING_SIGNED_AUDIT_KEY_STATUS_CHANGE_6";
    public final static String SYMKEY_GENERATION_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_SYMKEY_GEN_REQUEST_PROCESSED_6";
    public static final String SYMKEY_GENERATION_REQUEST =
            "LOGGING_SIGNED_AUDIT_SYMKEY_GENERATION_REQUEST_4";
    public static final String ASYMKEY_GENERATION_REQUEST =
            "LOGGING_SIGNED_AUDIT_ASYMKEY_GENERATION_REQUEST_4";
    public final static String ASYMKEY_GENERATION_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_ASYMKEY_GEN_REQUEST_PROCESSED_6";

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

    public final static String ACCESS_SESSION_ESTABLISH_FAILURE =
            "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_ESTABLISH_FAILURE";
    public final static String ACCESS_SESSION_ESTABLISH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_ESTABLISH_SUCCESS";
    public final static String ACCESS_SESSION_TERMINATED =
            "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_TERMINATED";
    public final static String AUDIT_LOG_SIGNING =
            "LOGGING_SIGNED_AUDIT_SIGNING_3";

    private static final long serialVersionUID = -844306657733902324L;
    private static final String INVALID_LOG_LEVEL = "log level: {0} is invalid, should be 0-6";

    protected Object mParams[] = null;

    private String mEventType = null;
    private String mMessage = null;
    private int mLevel = -1;
    private int mNTEventType = -1;
    private int mSource = -1;
    private boolean mMultiline = false;
    private long mTimeStamp = System.currentTimeMillis();

    /**
     * The bundle name for this event.
     */
    private String mBundleName = LogResources.class.getName();

    /**
     * Constructs a message event
     * <P>
     *
     * @param msgFormat the message string
     */
    public AuditEvent(String msgFormat) {
        mMessage = msgFormat;
        mParams = null;
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
        this(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
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
        this(msgFormat);
        mParams = new Exception[1];
        mParams[0] = exception;
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
        this(e.getMessage());
        if (e instanceof EBaseException) {
            mParams = ((EBaseException) e).getParameters();
        } else {
            mParams = new Exception[1];
            mParams[0] = e;
        }
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
        this(msgFormat);
        mParams = params;
    }

    /**
     * Returns the current message format string.
     * <P>
     *
     * @return details message
     */
    public String getMessage() {
        return mMessage;
    }

    /**
     * Returns a list of parameters.
     * <P>
     *
     * @return list of message format parameters
     */
    public Object[] getParameters() {
        return mParams;
    }

    /**
     * Sets a list of parameters.
     */
    public void setParameters(Object[] params) {
        mParams = params;
    }

    /**
     * Returns localized message string. This method should
     * only be called if a localized string is necessary.
     * <P>
     *
     * @return details message
     */
    public String toContent() {
        return toContent(Locale.getDefault());
    }

    /**
     * Returns the string based on the given locale.
     * <P>
     *
     * @param locale locale
     * @return details message
     */
    public String toContent(Locale locale) {
        return MessageFormatter.getLocalizedString(locale, getBundleName(),
                getMessage(),
                getParameters());
    }

    /**
     * Gets the resource bundle name for this class instance. This should
     * be overridden by subclasses who have their own resource bundles.
     *
     * @param bundle String that represents the resource bundle name to be set
     */
    public void setBundleName(String bundle) {
        mBundleName = bundle;
    }

    /**
     * Retrieves bundle name.
     *
     * @return a String that represents the resource bundle name
     */
    protected String getBundleName() {
        return mBundleName;
    }

    /**
     * Retrieves log source.
     *
     * @return an integer that indicates the component source
     *         where this message event was triggered
     */
    public int getSource() {
        return mSource;
    }

    /**
     * Sets log source.
     *
     * @param source an integer that represents the component source
     *            where this message event was triggered
     */
    public void setSource(int source) {
        mSource = source;
    }

    /**
     * Retrieves log level.
     * The log level of an event represents its relative importance
     * or severity within CMS.
     *
     * @return Integer log level value.
     */
    public int getLevel() {
        return mLevel;
    }

    /**
     * Retrieves NT specific log event type.
     *
     * @return Integer NTEventType value.
     */
    public int getNTEventType() {
        return mNTEventType;
    }

    /**
     * Sets log level, NT log event type.
     * For certain log levels the NT log event type gets
     * set as well.
     *
     * @param level Integer log level value.
     */
    public void setLevel(int level) {
        mLevel = level;
        switch (level) {
        case ILogger.LL_DEBUG:
        case ILogger.LL_INFO:
            mNTEventType = ILogger.NT_INFO;
            break;

        case ILogger.LL_WARN:
            mNTEventType = ILogger.NT_WARN;
            break;

        case ILogger.LL_FAILURE:
        case ILogger.LL_MISCONF:
        case ILogger.LL_CATASTRPHE:
        case ILogger.LL_SECURITY:
            mNTEventType = ILogger.NT_ERROR;
            break;

        default:
            ConsoleError.send(new SystemEvent(INVALID_LOG_LEVEL,
                    Integer.toString(level)));
            break;
        }
    }

    /**
     * Retrieves log multiline attribute.
     *
     * @return Boolean whether or not this event is multiline.
     *         A multiline message simply consists of more than one line.
     */
    public boolean getMultiline() {
        return mMultiline;
    }

    /**
     * Sets log multiline attribute. A multiline message consists of
     * more than one line.
     *
     * @param multiline Boolean multiline value.
     */
    public void setMultiline(boolean multiline) {
        mMultiline = multiline;
    }

    /**
     * Retrieves event time stamp.
     *
     * @return Long integer of the time the event was created.
     */
    public long getTimeStamp() {
        return mTimeStamp;
    }

    /**
     * Retrieves log event type. Each type of event
     * has an associated String type value.
     *
     * @return String containing the type of event.
     */
    public String getEventType() {
        return mEventType;
    }

    /**
     * Sets log event type. Each type of event
     * has an associated String type value.
     *
     * @param eventType String containing the type of event.
     */
    public void setEventType(String eventType) {
        mEventType = eventType;
    }

    /**
     * Return string representation of log message.
     *
     * @return String containing log message.
     */
    public String toString() {
        if (getBundleName() == null) {
            MessageFormat detailMessage = new MessageFormat(mMessage);

            return detailMessage.format(mParams);
            //return getMessage();
        } else
            return toContent();
    }
}
