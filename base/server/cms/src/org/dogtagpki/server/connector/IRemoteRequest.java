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

    public static final String SERVER_SIDE_KEYGEN = "serversideKeygen";
    public static final String TOKEN_CUID = "CUID";
    public static final String TOKEN_CARD_CHALLENGE = "card_challenge";
    public static final String TOKEN_HOST_CHALLENGE = "host_challenge";
    public static final String TOKEN_KEYINFO = "KeyInfo";
    public static final String TOKEN_CARD_CRYPTOGRAM = "card_cryptogram";
    public static final String TOKEN_KEYSET = "keySet";
    public static final String TOKEN_DATA_NUM_BYTES = "dataNumBytes";
    public static final String TOKEN_NEW_KEYINFO = "newKeyInfo";
    public static final String TOKEN_DATA = "data";

    public static final int RESPONSE_STATUS_NOT_FOUND = -1;
    public static final String RESPONSE_STATUS = "status";

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

}
