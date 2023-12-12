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
package com.netscape.cmscore.request;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

public class Request {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Request.class);

    public static final String REQ_VERSION = "requestVersion";

    public static final String REQ_STATUS = "requestStatus";
    public static final String REQ_TYPE = "requestType";
    public static final String REQ_FORMAT = "requestFormat";

    // request type values
    public static final String ENROLLMENT_REQUEST = "enrollment";
    public static final String RENEWAL_REQUEST = "renewal";
    public static final String REVOCATION_REQUEST = "revocation";
    public static final String CMCREVOKE_REQUEST = "CMCRevReq";
    public static final String UNREVOCATION_REQUEST = "unrevocation";
    public static final String KEYARCHIVAL_REQUEST = "archival";
    public static final String KEYRECOVERY_REQUEST = "recovery";
    public static final String KEY_RECOVERY_REQUEST = "keyRecovery";
    public static final String KEY_ARCHIVAL_REQUEST = "keyArchival";
    public static final String GETCACHAIN_REQUEST = "getCAChain";
    public static final String GETREVOCATIONINFO_REQUEST = "getRevocationInfo";
    public static final String GETCRL_REQUEST = "getCRL";
    public static final String GETCERTS_REQUEST = "getCertificates";
    public static final String REVOCATION_CHECK_CHALLENGE_REQUEST = "revocationChallenge";
    public static final String GETCERT_STATUS_REQUEST = "getCertStatus";
    public static final String GETCERTS_FOR_CHALLENGE_REQUEST = "getCertsForChallenge";
    public static final String CLA_CERT4CRL_REQUEST = "cert4crl";
    public static final String CLA_UNCERT4CRL_REQUEST = "uncert4crl";
    public static final String NETKEY_KEYGEN_REQUEST = "netkeyKeygen";
    public static final String NETKEY_KEYRECOVERY_REQUEST = "netkeyKeyRecovery";

    public static final String REQUESTOR_NAME = "csrRequestorName";
    public static final String REQUESTOR_PHONE = "csrRequestorPhone";
    public static final String REQUESTOR_EMAIL = "csrRequestorEmail";
    public static final String REQUESTOR_COMMENTS = "csrRequestorComments";

    // request attributes for all
    public static final String AUTH_TOKEN = "AUTH_TOKEN";
    public static final String HTTP_PARAMS = "HTTP_PARAMS";
    public static final String HTTP_HEADERS = "HTTP_HEADERS";

    // params added by agents on agent approval page
    public static final String AGENT_PARAMS = "AGENT_PARAMS";

    // server attributes: attributes generated by server modules
    public static final String SERVER_ATTRS = "SERVER_ATTRS";

    // sometimes individual AuthToken fields get set in request
    // extdata, with key ("auth_token." + field_name)
    public static final String AUTH_TOKEN_PREFIX = "auth_token";

    public static final String PROFILE_ID = "profileId";

    /**
     * ID of requested certificate authority (absence implies host authority)
     */
    public static final String AUTHORITY_ID = "req_authority_id";

    /**
     * Arbitrary user-supplied data that will be saved in request.
     */
    public static final String USER_DATA = "user_data";

    public static final String RESULT = "Result"; // service result.
    public static final Integer RES_SUCCESS = Integer.valueOf(1); // result value
    public static final Integer RES_ERROR = Integer.valueOf(2); // result value
    public static final String REMOTE_SERVICE_AUTHORITY = "RemServiceAuthority";
    public static final String SVCERRORS = "serviceErrors";
    public static final String REMOTE_STATUS = "remoteStatus";
    public static final String REMOTE_REQID = "remoteReqID";
    public static final String CERT_STATUS = "certStatus";

    // ChallengePhraseAuthentication
    public static final String CHALLENGE_PHRASE = "challengePhrase";
    public static final String SUBJECTNAME = "subjectName";
    public static final String SERIALNUMBER = "serialNumber";
    public static final String SERIALNOARRAY = "serialNoArray";

    // enrollment request attributes (from http request)
    public static final String CERT_TYPE = "certType";
    public static final String CRMF_REQID = "crmfReqId";
    public static final String PKCS10_REQID = "pkcs10ReqId";

    // CMC request attributes
    public static final String CMC_REQIDS = "cmcReqIds";
    public static final String CMC_TRANSID = "transactionId";
    public static final String CMC_SENDERNONCE = "senderNonce";
    public static final String CMC_RECIPIENTNONCE = "recipientNonce";
    public static final String CMC_REGINFO = "regInfo";

    // enrollment request attributes (generated internally)
    // also used for renewal
    public static final String CERT_INFO = "CERT_INFO";
    public static final String ISSUED_CERTS = "issuedCerts";
    public static final String REQUEST_TRUSTEDMGR_PRIVILEGE = "requestTrustedManagerPrivilege";
    public static final String FINGERPRINTS = "fingerprints";

    // enrollment request values
    public static final String SERVER_CERT = "server";
    public static final String CLIENT_CERT = "client";
    public static final String CA_CERT = "ca";
    public static final String RA_CERT = "ra";
    public static final String OCSP_CERT = "ocsp";
    public static final String OBJECT_SIGNING_CERT = "objSignClient";
    public static final String OTHER_CERT = "other";
    public static final String ROUTER_CERT = "router"; // deprecated
    public static final String CEP_CERT = "CEP-Request";

    // renewal request attributes. (internally set)
    // also used for revocation
    public static final String OLD_CERTS = "OLD_CERTS";
    public static final String OLD_SERIALS = "OLD_SERIALS";
    public static final String ISSUERDN = "issuerDN";

    // revocation request attributes (internally set)
    public static final String REVOKED_CERTS = "revokedCerts";
    public static final String REVOKED_REASON = "revocationReason";
    // CCA -> CLA request attributes
    public static final String REVOKED_CERT_RECORDS = "revokedCertRecs";
    // crl update status after a revocation.
    public static final String CRL_UPDATE_STATUS = "crlUpdateStatus";
    public static final String CRL_UPDATE_ERROR = "crlUpdateError";
    public static final String CRL_PUBLISH_STATUS = "crlPublishStatus";
    public static final String CRL_PUBLISH_ERROR = "crlPublishError";
    public static final String REQUESTOR_TYPE = "requestorType";

    // Netkey request attributes
    public static final String NETKEY_ATTR_CUID = "CUID";
    public static final String NETKEY_ATTR_USERID = "USERID";
    public static final String NETKEY_ATTR_DRMTRANS_DES_KEY = "drm_trans_desKey";
    public static final String NETKEY_ATTR_ARCHIVE_FLAG = "archive";
    public static final String NETKEY_ATTR_DRMTRANS_AES_KEY = "drm_trans_aesKey";
    public static final String NETKEY_ATTR_SSKEYGEN_AES_KEY_WRAP_ALG = "drm_aes_wrapAlg";

    public static final String NETKEY_ATTR_SERVERSIDE_MUSCLE_FLAG = "serverSideMuscle";
    public static final String NETKEY_ATTR_ENC_PRIVKEY_FLAG = "encryptPrivKey";
    public static final String NETKEY_ATTR_USER_CERT = "cert";
    public static final String NETKEY_ATTR_KEYID = "keyid";
    public static final String NETKEY_ATTR_KEY_SIZE = "keysize";
    public static final String NETKEY_ATTR_KEY_TYPE = "keytype";
    public static final String NETKEY_ATTR_KEY_EC_CURVE = "eckeycurve";

    // security data request attributes
    public static final String SECURITY_DATA_ENROLLMENT_REQUEST = "securityDataEnrollment";
    public static final String SECURITY_DATA_RECOVERY_REQUEST = "securityDataRecovery";
    public static final String SECURITY_DATA_CLIENT_KEY_ID = "clientKeyID";
    public static final String SECURITY_DATA_STRENGTH = "strength";
    public static final String SECURITY_DATA_ALGORITHM = "algorithm";
    public static final String SECURITY_DATA_TYPE = "dataType";
    public static final String SECURITY_DATA_STATUS = "status";
    public static final String SECURITY_DATA_TRANS_SESS_KEY = "transWrappedSessionKey";
    public static final String SECURITY_DATA_SESS_PASS_PHRASE = "sessionWrappedPassphrase";
    public static final String SECURITY_DATA_IV_STRING_IN = "iv_in";
    public static final String SECURITY_DATA_IV_STRING_OUT = "iv_out";
    public static final String SECURITY_DATA_SESS_WRAPPED_DATA = "sessWrappedSecData";
    public static final String SECURITY_DATA_PASS_WRAPPED_DATA = "passPhraseWrappedData";
    public static final String SECURITY_DATA_PL_ENCRYPTION_OID = "payloadEncryptionOID";
    public static final String SECURITY_DATA_PL_WRAPPING_NAME = "payloadWrappingName";
    public static final String SECURITY_DATA_PL_WRAPPED = "payloadWrapped";

    // key generation request attributes
    public static final String ASYMKEY_GENERATION_REQUEST = "asymkeyGenRequest";
    public static final String SYMKEY_GENERATION_REQUEST = "symkeyGenRequest";
    public static final String KEY_GEN_ALGORITHM = "keyGenAlgorithm";
    public static final String KEY_GEN_SIZE = "keyGenSize";
    public static final String KEY_GEN_USAGES = "keyGenUsages";
    public static final String KEY_GEN_TRANS_WRAPPED_SESSION_KEY = "transWrappedSessionKey";

    // server-side keygen enrollment
    //public static final String SERVER_SIDE_KEYGEN_ENROLL = "serverSideKeygenEnroll";
    public static final String SERVER_SIDE_KEYGEN_ENROLL_ENABLE_ARCHIVAL = "serverSideKeygenEnrollEnableArchival";
    public static final String SSK_STAGE = "serverSideKeygenStage";
    public static final String SSK_STAGE_KEYGEN = "serverSideKeygenStage_keygen";
    public static final String SSK_STAGE_KEY_RETRIEVE = "serverSideKeygenStage_key_retrieve";

    // requestor type values
    public static final String REQUESTOR_EE = "EE";
    public static final String REQUESTOR_RA = "RA";
    public static final String REQUESTOR_NETKEY_RA = "NETKEY_RA";
    public static final String REQUESTOR_KRA = "KRA";
    public static final String REQUESTOR_AGENT = "Agent";

    // others  (internally set)
    public static final String CACERTCHAIN = "CACertChain";
    public static final String CRL = "CRL";
    public static final String DOGETCACHAIN = "doGetCAChain";
    public static final String CERT_FILTER = "certFilter";

    // used by policy
    public static final String ERRORS = "errors";
    public static final String SMIME = "SMIME";
    public static final String OBJECT_SIGNING = "ObjectSigning";
    public static final String SSL_CLIENT = "SSLClient";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Subject Name.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateSubjectName
     */
    public static final String REQUEST_SUBJECT_NAME = "req_subject_name";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Key.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateX509Key
     */
    public static final String REQUEST_KEY = "req_key";

    /**
     * Name of request attribute that stores the transport certificate.
     *
     * The value is of type String including base64 encoded certificate.
     */
    public static final String REQUEST_TRANSPORT_CERT = "req_transport_cert";

    /**
     * Name of request attribute that stores the End-User Supplied
     * PKI Archive Option extension. This extension is extracted
     * from a CRMF request that has the user-provided private key.
     *
     * The value is of type byte []
     */
    public static final String REQUEST_ARCHIVE_OPTIONS = "req_archive_options";

    /**
     * Transport Key wrapped session key passed into DRM archival service.
     */
    public static final String REQUEST_SESSION_KEY = "req_session_key";

    /**
     * Session wrapped security data passed in to the DRM archival service
     */
    public static final String REQUEST_SECURITY_DATA = "req_security_data";

    /**
     * Symmetric key algorithm params passed into DRM archival service
     */
    public static final String REQUEST_ALGORITHM_PARAMS = "req_algorithm_params";

    /**
     * Symmetric Key algorithm OID passed into DRM archival service
     */
    public static final String REQUEST_ALGORITHM_OID = "req_algorithm_oid";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Validity.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateValidity
     */
    public static final String REQUEST_VALIDITY = "req_validity";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Signing Algorithm.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId
     */
    public static final String REQUEST_SIGNING_ALGORITHM = "req_signing_alg";

    /**
     * Name of request attribute that stores the End-User Supplied
     * Extensions.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.CertificateExtensions
     */
    public static final String REQUEST_EXTENSIONS = "req_extensions";

    /**
     * Name of request attribute that stores the certificate template
     * that will be signed and then become a certificate.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.X509CertInfo
     */
    public static final String REQUEST_CERTINFO = "req_x509info";

    /**
     * Name of request attribute that stores the issued certificate.
     *
     * The value is of type org.mozilla.jss.netscape.security.x509.X509CertImpl
     */
    public static final String REQUEST_ISSUED_CERT = "req_issued_cert";

    /**
     * Name of request attribute that stores the User
     * Supplied Certificate Request.
     */
    public static final String CTX_CERT_REQUEST = "cert_request";

    // attribute names for performing searches
    public final static String ATTR_REQUEST_OWNER = "requestOwner";
    public final static String ATTR_REQUEST_STATUS = "requestStatus";
    public final static String ATTR_SOURCE_ID = "requestSourceId";
    public final static String ATTR_REQUEST_TYPE = "requestType";

    // for async recovery
    public final static String ATTR_APPROVE_AGENTS = "approvingAgents";

    /**
     * Other attributes stored in the attribute set
     */
    public final static String UPDATED_BY = "updatedBy";

    // error message
    public static final String ERROR = "Error";

    // request error code
    public static final String ERROR_CODE = "errorCode";

    // authentication realm
    public static final String REALM = "realm";

    protected RequestId mRequestId;
    protected RequestStatus mRequestStatus;
    protected String mSourceId;
    protected String mSource;
    protected String mOwner;
    protected String mRequestType;
    protected String mContext; // string for now.
    protected String realm;
    protected ExtDataHashtable<Object> mExtData = new ExtDataHashtable<>();

    Date mCreationTime = new Date();
    Date mModificationTime = new Date();

    public Request(RequestId id) {
        mRequestId = id;
        setRequestStatus(RequestStatus.BEGIN);
    }

    public RequestId getRequestId() {
        return mRequestId;
    }

    public RequestStatus getRequestStatus() {
        return mRequestStatus;
    }

    // Obsolete
    public void setRequestStatus(RequestStatus s) {
        mRequestStatus = s;
        // expose request status so that we can do predicate upon it
        setExtData(Request.REQ_STATUS, s.toString());
    }

    public boolean isSuccess() {
        Integer result = getExtDataInInteger(Request.RESULT);
        return result != null && result.equals(Request.RES_SUCCESS);
    }

    public String getError(Locale locale) {
        return getExtDataInString(Request.ERROR);
    }

    public String getErrorCode(Locale locale) {
        return getExtDataInString(Request.ERROR_CODE);
    }

    public String getSourceId() {
        return mSourceId;
    }

    public void setSourceId(String id) {
        mSourceId = id;
    }

    public String getRequestOwner() {
        return mOwner;
    }

    public void setRequestOwner(String id) {
        mOwner = id;
    }

    public String getRequestType() {
        return mRequestType;
    }

    public void setRequestType(String type) {
        mRequestType = type;
        setExtData(Request.REQ_TYPE, type);
    }

    public String getRequestVersion() {
        return getExtDataInString(Request.REQ_VERSION);
    }

    public Date getCreationTime() {
        return mCreationTime;
    }

    public void setCreationTime(Date date) {
        mCreationTime = date;
    }

    public String getContext() {
        return mContext;
    }

    public void setContext(String ctx) {
        mContext = ctx;
    }

    public Date getModificationTime() {
        return mModificationTime;
    }

    public void setModificationTime(Date date) {
        mModificationTime = date;
    }

    /**
     * Copies meta attributes (excluding request ID, etc.) of another request
     * to this request.
     *
     * @param req another request
     */
    public void copyContents(Request req) {
        // this isn't that efficient but will do for now.
        Enumeration<String> e = req.getExtDataKeys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            if (!key.equals(Request.ISSUED_CERTS) &&
                    !key.equals(Request.ERRORS) &&
                    !key.equals(Request.REMOTE_REQID)) {
                if (req.isSimpleExtDataValue(key)) {
                    setExtData(key, req.getExtDataInString(key));
                } else {
                    setExtData(key, req.getExtDataInHashtable(key));
                }
            }
        }
    }

    /**
     * This function used to check that the keys obeyed LDAP attribute name
     * syntax rules. Keys are being encoded now, so it is changed to just
     * filter out null and empty string keys.
     *
     * @param key The key to check
     * @return false if invalid
     */
    protected boolean isValidExtDataKey(String key) {
        return key != null &&
                (!key.equals(""));
    }

    protected boolean isValidExtDataHashtableValue(Hashtable<String, String> hash) {
        if (hash == null) {
            return false;
        }
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            Object key = keys.nextElement();
            if (!((key instanceof String) && isValidExtDataKey((String) key))) {
                return false;
            }
            /*
             * 	TODO  should the Value type be String?
             */
            Object value = hash.get(key);
            if (!(value instanceof String)) {
                return false;
            }
        }

        return true;
    }

    public boolean setExtData(String key, String value) {
        if (!isValidExtDataKey(key)) {
            return false;
        }
        if (value == null) {
            return false;
        }

        mExtData.put(key, value);
        return true;
    }

    public boolean setExtData(String key, Hashtable<String, String> value) {
        if (!(isValidExtDataKey(key) && isValidExtDataHashtableValue(value))) {
            return false;
        }

        mExtData.put(key, new ExtDataHashtable<>(value));
        return true;
    }

    public boolean isSimpleExtDataValue(String key) {
        return (mExtData.get(key) instanceof String);
    }

    public String getExtDataInString(String key) {
        Object value = mExtData.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String)) {
            return null;
        }
        return (String) value;
    }

    @SuppressWarnings("unchecked")
    public Hashtable<String, String> getExtDataInHashtable(String key) {
        Object value = mExtData.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Hashtable)) {
            return null;
        }
        return new ExtDataHashtable<>((Hashtable<String, String>) value);
    }

    public Enumeration<String> getExtDataKeys() {
        return mExtData.keys();
    }

    public void deleteExtData(String type) {
        mExtData.remove(type);
    }

    public boolean setExtData(String key, String subkey, String value) {
        if (!(isValidExtDataKey(key) && isValidExtDataKey(subkey))) {
            return false;
        }
        if (isSimpleExtDataValue(key)) {
            return false;
        }
        if (value == null) {
            return false;
        }

        @SuppressWarnings("unchecked")
        Hashtable<String, String> existingValue = (Hashtable<String, String>) mExtData.get(key);
        if (existingValue == null) {
            existingValue = new ExtDataHashtable<>();
            mExtData.put(key, existingValue);
        }
        existingValue.put(subkey, value);
        return true;
    }

    public String getExtDataInString(String key, String subkey) {
        Hashtable<String, String> value = getExtDataInHashtable(key);
        if (value == null) {
            return null;
        }
        return value.get(subkey);
    }

    public boolean setExtData(String key, Integer value) {
        if (value == null) {
            return false;
        }
        return setExtData(key, value.toString());
    }

    public Integer getExtDataInInteger(String key) {
        String strVal = getExtDataInString(key);
        if (strVal == null) {
            return null;
        }
        try {
            return Integer.valueOf(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean setExtData(String key, Integer[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            stringArray[index] = data[index].toString();
        }
        return setExtData(key, stringArray);
    }

    public Integer[] getExtDataInIntegerArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        Integer[] intArray = new Integer[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                intArray[index] = Integer.valueOf(stringArray[index]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return intArray;
    }

    public boolean setExtData(String key, BigInteger value) {
        if (value == null) {
            return false;
        }
        return setExtData(key, value.toString());
    }

    public BigInteger getExtDataInBigInteger(String key) {
        String strVal = getExtDataInString(key);
        if (strVal == null) {
            return null;
        }
        try {
            return new BigInteger(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean setExtData(String key, BigInteger[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            stringArray[index] = data[index].toString();
        }
        return setExtData(key, stringArray);
    }

    public BigInteger[] getExtDataInBigIntegerArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        BigInteger[] intArray = new BigInteger[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                intArray[index] = new BigInteger(stringArray[index]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return intArray;
    }

    public boolean setExtData(String key, Throwable e) {
        if (e == null) {
            return false;
        }
        return setExtData(key, e.toString());
    }

    public boolean setExtData(String key, byte[] data) {
        if (data == null) {
            return false;
        }
        return setExtData(key, Utils.base64encode(data, true));
    }

    public byte[] getExtDataInByteArray(String key) {
        String value = getExtDataInString(key);
        if (value != null) {
            return Utils.base64decode(value);
        }
        return null;
    }

    public boolean setExtData(String key, X509CertImpl data) {
        if (data == null) {
            return false;
        }
        try {
            return setExtData(key, data.getEncoded());
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    public X509CertImpl getExtDataInCert(String key) {
        byte[] data = getExtDataInByteArray(key);
        if (data != null) {
            try {
                return new X509CertImpl(data);
            } catch (CertificateException e) {
                logger.warn("Request: getExtDataInCert(): " + e.getMessage(), e);
                return null;
            }
        }
        return null;
    }

    public boolean setExtData(String key, X509CertImpl[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = Utils.base64encode(data[index].getEncoded(), true);
            } catch (CertificateEncodingException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    public X509CertImpl[] getExtDataInCertArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        X509CertImpl[] certArray = new X509CertImpl[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new X509CertImpl(Utils.base64decode(stringArray[index]));
            } catch (CertificateException e) {
                logger.warn("Request: getExtDataInCertArray(): " + e.getMessage(), e);
                return null;
            }
        }
        return certArray;
    }

    public boolean setExtData(String key, X509CertInfo data) {
        if (data == null) {
            return false;
        }
        try {
            return setExtData(key, data.getEncodedInfo(true));
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    public X509CertInfo getExtDataInCertInfo(String key) {
        byte[] data = getExtDataInByteArray(key);
        if (data != null) {
            try {
                return new X509CertInfo(data);
            } catch (CertificateException e) {
                logger.warn("Request: getExtDataInCertInfo(): " + e.getMessage(), e);
                return null;
            }
        }
        return null;
    }

    public boolean setExtData(String key, X509CertInfo[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = Utils.base64encode(data[index].getEncodedInfo(true), true);
            } catch (CertificateEncodingException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    public X509CertInfo[] getExtDataInCertInfoArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        X509CertInfo[] certArray = new X509CertInfo[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new X509CertInfo(Utils.base64decode(stringArray[index]));
            } catch (CertificateException e) {
                logger.warn("Request: getExtDataInCertInfoArray(): " + e.getMessage(), e);
                return null;
            }
        }
        return certArray;
    }

    public boolean setExtData(String key, RevokedCertImpl[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = Utils.base64encode(data[index].getEncoded(), true);
            } catch (CRLException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    public RevokedCertImpl[] getExtDataInRevokedCertArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        RevokedCertImpl[] certArray = new RevokedCertImpl[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new RevokedCertImpl(Utils.base64decode(stringArray[index]));
            } catch (CRLException e) {
                return null;
            } catch (X509ExtensionException e) {
                return null;
            }
        }
        return certArray;
    }

    public boolean setExtData(String key, Vector<?> stringVector) {
        String[] stringArray;
        if (stringVector == null) {
            return false;
        }
        try {
            stringArray = stringVector.toArray(new String[0]);
        } catch (ArrayStoreException e) {
            return false;
        }
        return setExtData(key, stringArray);
    }

    public Vector<String> getExtDataInStringVector(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        return new Vector<>(Arrays.asList(stringArray));
    }

    public boolean getExtDataInBoolean(String key, boolean defVal) {
        String val = getExtDataInString(key);
        if (val == null)
            return defVal;
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("ON");
    }

    public boolean getExtDataInBoolean(String prefix, String type, boolean defVal) {
        String val = getExtDataInString(prefix, type);
        if (val == null)
            return defVal;
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("ON");
    }

    public boolean setExtData(String key, AuthToken data) {
        if (data == null) {
            return false;
        }
        Hashtable<String, String> hash = new Hashtable<>();
        Enumeration<String> keys = data.getElements();
        while (keys.hasMoreElements()) {
            try {
                String authKey = keys.nextElement();
                hash.put(authKey, data.getInString(authKey));
            } catch (ClassCastException e) {
                return false;
            }
        }
        return setExtData(key, hash);
    }

    public AuthToken getExtDataInAuthToken(String key) {
        Hashtable<String, String> hash = getExtDataInHashtable(key);
        if (hash == null) {
            return null;
        }
        AuthToken authToken = new AuthToken(null);
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            try {
                String hashKey = keys.nextElement();
                authToken.set(hashKey, hash.get(hashKey));
            } catch (ClassCastException e) {
                return null;
            }
        }
        return authToken;
    }

    public boolean setExtData(String key, CertificateExtensions data) {
        if (data == null) {
            return false;
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            data.encode(byteStream);
        } catch (CertificateException e) {
            logger.warn("Request: setExtData(): " + e.getMessage(), e);
            return false;
        } catch (IOException e) {
            logger.warn("Request: setExtData(): " + e.getMessage(), e);
            return false;
        }
        return setExtData(key, byteStream.toByteArray());
    }

    public CertificateExtensions getExtDataInCertExts(String key) {
        CertificateExtensions exts = null;
        byte[] extensionsData = getExtDataInByteArray(key);
        if (extensionsData != null) {
            exts = new CertificateExtensions();
            try {
                exts.decodeEx(new ByteArrayInputStream(extensionsData));
                // exts.decode() does not work when the CertExts size is 0
                // exts.decode(new ByteArrayInputStream(extensionsData));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return exts;
    }

    public boolean setExtData(String key, CertificateSubjectName data) {
        if (data == null) {
            return false;
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            data.encode(byteStream);
        } catch (IOException e) {
            return false;
        }
        return setExtData(key, byteStream.toByteArray());
    }

    public CertificateSubjectName getExtDataInCertSubjectName(String key) {
        CertificateSubjectName name = null;
        byte[] nameData = getExtDataInByteArray(key);
        if (nameData != null) {
            try {
                // You must use DerInputStream
                // using ByteArrayInputStream fails
                name = new CertificateSubjectName(
                        new DerInputStream(nameData));
            } catch (IOException e) {
                return null;
            }
        }
        return name;
    }

    public boolean setExtData(String key, String[] values) {
        if (values == null) {
            return false;
        }
        Hashtable<String, String> hashValue = new Hashtable<>();
        for (int index = 0; index < values.length; index++) {
            hashValue.put(Integer.toString(index), values[index]);
        }
        return setExtData(key, hashValue);
    }

    public String[] getExtDataInStringArray(String key) {
        int index;

        Hashtable<String, String> hashValue = getExtDataInHashtable(key);
        if (hashValue == null) {
            String s = getExtDataInString(key);
            return s == null ? null : new String[] { s };
        }
        Set<String> arrayKeys = hashValue.keySet();
        Vector<Object> listValue = new Vector<>(arrayKeys.size());
        for (Iterator<String> iter = arrayKeys.iterator(); iter.hasNext();) {
            String arrayKey = iter.next();
            try {
                index = Integer.parseInt(arrayKey);
            } catch (NumberFormatException e) {
                return null;
            }
            if (listValue.size() < (index + 1)) {
                listValue.setSize(index + 1);
            }
            listValue.set(index,
                    hashValue.get(arrayKey));
        }
        return listValue.toArray(new String[0]);
    }

    public IAttrSet asIAttrSet() {
        return new RequestIAttrSetWrapper(this);
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }
}
