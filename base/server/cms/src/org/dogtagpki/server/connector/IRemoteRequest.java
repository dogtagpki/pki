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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.connector;

/**
 * IRemoteRequest is the interface class for the remote
 *     requests and responses
 *
 * @author cfu
 */
public interface IRemoteRequest {
//    public static final String TOKEN_CUID = "CUID";
    public static final String TOKEN_CUID = "tokencuid";
    public static final String GET_XML = "xml";
    public static final int RESPONSE_STATUS_NOT_FOUND = -1;
    public static final String RESPONSE_STATUS = "status";
    public static final String RESPONSE_ERROR_STRING = "error";
    public static final String RESPONSE_STATUS_XML = "Status";

    // TKS request params
    public static final String SERVER_SIDE_KEYGEN = "serversideKeygen";
    public static final String TOKEN_CARD_CHALLENGE = "card_challenge";
    public static final String TOKEN_HOST_CHALLENGE = "host_challenge";
    public static final String TOKEN_KEYINFO = "KeyInfo";
    public static final String TOKEN_CARD_CRYPTOGRAM = "card_cryptogram";
    public static final String TOKEN_KEYSET = "keySet";
    public static final String TOKEN_DATA_NUM_BYTES = "dataNumBytes";
    public static final String TOKEN_NEW_KEYINFO = "newKeyInfo";
    public static final String TOKEN_DATA = "data";

    // TKS response params
    /* computeSessionKey responses */
    public static final String TKS_RESPONSE_SessionKey = "sessionKey";
    public static final String TKS_RESPONSE_EncSessionKey = "encSessionKey";
    public static final String TKS_RESPONSE_KEK_DesKey = "kek_wrapped_desKey";
    public static final String TKS_RESPONSE_DRM_Trans_DesKey = "drm_trans_wrapped_desKey";
    public static final String TKS_RESPONSE_KeyCheck = "keycheck";
    public static final String TKS_RESPONSE_HostCryptogram = "hostCryptogram";

    /* createKeySetData response */
    public static final String TKS_RESPONSE_KeySetData = "keySetData";

    /* encryptData response */
    public static final String TKS_RESPONSE_EncryptedData = "encryptedData";

    /* computeRandomData response */
    public static final String TKS_RESPONSE_RandomData = "randomData";

    // CA request params
    public static final String CA_ProfileId = "profileId";
    public static final String CA_ENROLL_screenname = "screenname";
    public static final String CA_ENROLL_publickey = "publickey";
    public static final String CA_RenewedCertificate = "renewedCertificate";
    public static final String CA_RENEWAL_SerialNum = "serial_num";
    public static final String CA_RENEWAL= "renewal";

    public static final String CA_REVOKE = "revoke";
    public static final String CA_REVOCATION_REASON = "revocationReason";
    public static final String CA_REVOKE_ALL = "revokeAll";
    public static final String CA_REVOKE_SERIAL = "certRecordId";
    public static final String CA_REVOKE_COUNT = "totalRecordCount";
    public static final String CA_REVOKE_INVALID_DATE = "invalidityDate";
    public static final String CA_REVOKE_REQUESTER_COMMENTS = "revRequesterComments";
    public static final String CA_REVOKE_REQUESTER_ID = "revRequesterID";
    public static final String CA_UNREVOKE_SERIAL = "serialNumber";

    // CA response params
    public static final String CA_OP = "op";
    public static final String CA_RESPONSE_Certificate_x509 = "X509Certificate";
    public static final String CA_RESPONSE_Certificate_b64 = "b64";
    public static final String CA_RESPONSE_Certificate_SubjectDN = "SubjectDN";
    public static final String CA_RESPONSE_Certificate_serial = "serialno";

    // KRA request params
    public static final String KRA_UserId = "userid";
    public static final String KRA_Trans_DesKey = "drm_trans_desKey";
    public static final String KRA_KEYGEN_Archive = "archive";
    public static final String KRA_KEYGEN_KeyType = "keytype";
    public static final String KRA_KEYGEN_EC_KeyCurve = "eckeycurve";
    public static final String KRA_KEYGEN_KeySize = "keysize";
    public static final String KRA_RECOVERY_CERT = "cert";
    public static final String KRA_RECOVERY_KEYID = "keyid";

    // KRA response params
    public static final String KRA_RESPONSE_PublicKey = "public_key";
    public static final String KRA_RESPONSE_Wrapped_PrivKey = "wrapped_priv_key";
    public static final String KRA_RESPONSE_IV_Param = "iv_param";
}
