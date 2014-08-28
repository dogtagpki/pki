//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.key;

import java.net.URISyntaxException;
import java.util.List;

import javax.ws.rs.core.Response;

import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.CryptoProvider;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author Endi S. Dewata
 * @author Abhishek Koneru
 */
public class KeyClient extends Client {

    public KeyResource keyClient;
    public KeyRequestResource keyRequestClient;

    private CryptoProvider crypto;
    private String transportCert;

    public KeyClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "key");
        init();
        this.crypto = client.getCrypto();
    }

    public void init() throws URISyntaxException {
        keyClient = createProxy(KeyResource.class);
        keyRequestClient = createProxy(KeyRequestResource.class);
    }

    public CryptoProvider getCrypto() {
        return crypto;
    }

    public void setCrypto(CryptoProvider crypto) {
        this.crypto = crypto;
    }

    /**
     * Set the value of the transport cert.
     * The HEADER and FOOTER should be removed from the string.
     * HEADER - CertData.HEADER
     * FOOTER - CertData.FOOTER
     *
     * @param transportCert
     */
    public void setTransportCert(String transportCert) {
        this.transportCert = transportCert;
    }

    /**
     * List/Search archived secrets in the DRM.
     *
     * @param clientKeyID -- Client Key Identifier
     * @param status -- Status of the keys to be listed
     * @param maxSize -- Maximum number of keys to be fetched
     * @param maxTime -- Maximum time for the operation to take
     * @param start -- Start index of list
     * @param size -- Size of the list to be returned.
     * @return a KeyInfoCollection object.
     */
    public KeyInfoCollection listKeys(String clientKeyID, String status, Integer maxSize, Integer maxTime,
            Integer start, Integer size) {
        Response response = keyClient.listKeys(clientKeyID, status, maxSize, maxTime, start, size);
        return client.getEntity(response, KeyInfoCollection.class);
    }

    /**
     * Search key requests in the DRM based on the state/type of the requests.
     *
     * @param requestState -- State of the requests to be queried.
     * @param requestType -- Type of the requests to be queried.
     * @return a KeyRequestCollection object.
     */
    public KeyRequestInfoCollection listRequests(String requestState, String requestType) {
        return listRequests(
                requestState,
                requestType,
                null,
                new RequestId(0),
                100,
                100,
                10);
    }

    /**
     * List/Search key requests in the DRM
     *
     * @param requestState -- State of the requests to be queried.
     * @param requestType -- Type of the requests to be queried.
     * @param clientKeyID -- Client Key Identifier
     * @param start -- Start index of list
     * @param pageSize -- Size of the list to be returned.
     * @param maxResults -- Maximum number of requests to be fetched
     * @param maxTime -- Maximum time for the operation to take
     * @return a KeyRequestInfoCollection object.
     */
    public KeyRequestInfoCollection listRequests(
            String requestState,
            String requestType,
            String clientKeyID,
            RequestId start,
            Integer pageSize,
            Integer maxResults,
            Integer maxTime) {
        Response response = keyRequestClient.listRequests(
                requestState,
                requestType,
                clientKeyID,
                start,
                pageSize,
                maxResults,
                maxTime);
        return client.getEntity(response, KeyRequestInfoCollection.class);
    }

    /**
     * Return a KeyRequestInfo object for a specific request.
     *
     * @param id -- A Request Id object
     * @return the KeyRequestInfo object for a specific request.
     */
    public KeyRequestInfo getRequestInfo(RequestId id) {
        if (id == null) {
            throw new IllegalArgumentException("Request Id must be specified.");
        }
        Response response = keyRequestClient.getRequestInfo(id);
        return client.getEntity(response, KeyRequestInfo.class);
    }

    /**
     * Get the info in the KeyRecord for a specific secret in the DRM.
     *
     * @param id -- key id for secret
     * @return the KeyInfo object for a specific request.
     */
    public KeyInfo getKeyInfo(KeyId id) {
        if (id == null) {
            throw new IllegalArgumentException("Key Id must be specified.");
        }
        Response response = keyClient.getKeyInfo(id);
        return client.getEntity(response, KeyInfo.class);
    }

    /**
     * Get the info in the KeyRecord for the active secret in the DRM.
     *
     * @param clientKeyID -- Client Key Identifier
     * @return
     */
    public KeyInfo getActiveKeyInfo(String clientKeyID) {
        if (clientKeyID == null) {
            throw new IllegalArgumentException("Client Key Id must be specified.");
        }
        Response response = keyClient.getActiveKeyInfo(clientKeyID);
        return client.getEntity(response, KeyInfo.class);
    }

    /**
     * Modify the status of a key
     *
     * @param id -- key id for secret
     * @param status -- Status to be set for the key
     */
    public void modifyKeyStatus(KeyId id, String status) {
        if (id == null || status == null) {
            throw new IllegalArgumentException("Key Id and status must be specified.");
        }
        if (!status.equalsIgnoreCase(KeyResource.KEY_STATUS_ACTIVE)
                && !status.equalsIgnoreCase(KeyResource.KEY_STATUS_INACTIVE)) {
            throw new IllegalArgumentException("Invalid status value.");
        }
        Response response = keyClient.modifyKeyStatus(id, status);
        client.getEntity(response, Void.class);
    }

    /**
     * Approve a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void approveRequest(RequestId id) {
        if (id == null) {
            throw new IllegalArgumentException("Request Id must be specified.");
        }
        Response response = keyRequestClient.approveRequest(id);
        client.getEntity(response, Void.class);
    }

    /**
     * Reject a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void rejectRequest(RequestId id) {
        if (id == null) {
            throw new IllegalArgumentException("Request Id must be specified.");
        }
        Response response = keyRequestClient.rejectRequest(id);
        client.getEntity(response, Void.class);
    }

    /**
     * Cancel a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void cancelRequest(RequestId id) {
        if (id == null) {
            throw new IllegalArgumentException("Request Id must be specified.");
        }
        Response response = keyRequestClient.cancelRequest(id);
        client.getEntity(response, Void.class);
    }

    /**
     * Submit an archival, recovery or key generation request
     * to the DRM.
     *
     * @param data -- A KeyArchivalRequest/KeyRecoveryRequest/SymKeyGenerationRequest object
     * @return A KeyRequestResponse object
     */
    private KeyRequestResponse submitRequest(ResourceMessage request) {
        if (request == null) {
            throw new IllegalArgumentException("A Request object must be specified.");
        }
        Response response = keyRequestClient.submitRequest(request);
        return client.getEntity(response, KeyRequestResponse.class);
    }

    /**
     * Create a request to recover a secret.
     *
     * To retrieve a symmetric key or passphrase, the only parameter that is required is
     * the KeyId object. It is possible (but not required) to pass in the session keys/passphrase
     * and nonceData for the retrieval at this time.
     *
     * To retrieve an asymmetric key, the keyId and the the base-64 encoded certificate
     * is required.
     *
     * @param keyId -- key id for secret
     * @param sessionWrappedPassphrase -- A passphrase wrapped by a session key
     * @param transWrappedSessionKey -- The session key, used to wrap the passphrase, wrapped by the DRM transport cert.
     * @param nonceData -- IV parameter used while encrypting the passphrase using the session key.
     * @param b64Certificate -- A certificate in encoded using Base64
     * @return A KeyRequestResponse object containing information about the key request and the key.
     */
    public KeyRequestResponse recoverKey(KeyId keyId, byte[] sessionWrappedPassphrase, byte[] transWrappedSessionKey,
            byte[] nonceData, String b64Certificate) {
        // create recovery request
        if (keyId == null) {
            throw new IllegalArgumentException("KeyId nust be specified.");
        }
        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(keyId);
        if (sessionWrappedPassphrase != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(sessionWrappedPassphrase));
        }
        if (transWrappedSessionKey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey));
        }

        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData));
        }
        if (b64Certificate != null) {
            data.setCertificate(b64Certificate);
        }

        return submitRequest(data);
    }

    /**
     * Retrieve a secret from the DRM.
     *
     * @param data -- a KeyRecoveryRequest containing the keyId of the
     *            secret being retrieved, the request_id of the approved recovery
     *            request and a wrapping mechanism.
     * @return A Key object containing the wrapped secret.
     */
    public Key retrieveKeyData(KeyRecoveryRequest data) {
        if (data == null) {
            throw new IllegalArgumentException("A KeyRecoveryRequest object must be specified");
        }
        Response response = keyClient.retrieveKey(data);
        return new Key(client.getEntity(response, KeyData.class));
    }

    /**
     * Retrieve a secret (passphrase or symmetric key) from the DRM.
     *
     * To ensure data security in transit, the data will be returned encrypted by a session
     * key (168 bit 3DES symmetric key) - which is first wrapped (encrypted) by the public
     * key of the DRM transport certificate before being sent to the DRM.
     *
     * This method will call CryptoUtil methods to generate the session key and wrap it
     * with the DRM transport cert. The function will return the Key object, but with the secret
     * set to the variable data. (The decryption of the encryptedData is done
     * on the client side i.e. the secret is not transmitted as it is by the server.)
     *
     * @param keyId -- key id for secret
     * @return A Key object containing the unwrapped secret (set to the attribute data).
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public Key retrieveKey(KeyId keyId) throws Exception {
        if (keyId == null) {
            throw new IllegalArgumentException("KeyId must be specified.");
        }
        SymmetricKey sessionKey = crypto.generateSessionKey();
        byte[] transWrappedSessionKey = crypto.wrapSessionKeyWithTransportCert(sessionKey, transportCert);

        Key data = retrieveKey(keyId, transWrappedSessionKey);

        data.setData(crypto.unwrapWithSessionKey(data.getEncryptedData(), sessionKey,
                KeyRequestResource.DES3_ALGORITHM, data.getNonceData()));

        return data;
    }

    /**
     * Retrieve a secret (passphrase or symmetric key) from the DRM.
     *
     * This function generates a key recovery request, approves it, and retrieves
     * the secret referred to by keyId.
     * This assumes that only one approval is required to authorize the recovery.
     *
     * The parameter transWrappedSessionKey refers to the session key wrapped with the transport cert.
     *
     * The method will simply pass the data to the DRM, and will return the secret
     * wrapped in the session key. The secret will still need to be unwrapped by the caller.
     *
     * @param keyId -- key id for secret
     * @param transWrappedSessionKey -- session key wrapped by the transport cert.
     * @return A Key object containing the wrapped secret.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public Key retrieveKey(KeyId keyId, byte[] transWrappedSessionKey) throws Exception {

        if (keyId == null) {
            throw new IllegalArgumentException("KeyId must be specified.");
        }
        if (transWrappedSessionKey == null) {
            throw new IllegalArgumentException("A transport cert wrapped session key cannot be null.");
        }

        KeyRequestResponse keyData = recoverKey(keyId, null, null, null, null);
        approveRequest(keyData.getRequestId());

        KeyRecoveryRequest recoveryRequest = new KeyRecoveryRequest();
        recoveryRequest.setKeyId(keyId);
        recoveryRequest.setRequestId(keyData.getRequestId());
        recoveryRequest.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey));

        return retrieveKeyData(recoveryRequest);
    }

    /**
     *
     * The secret is secured in transit by wrapping the secret with the passphrase using
     * PBE encryption.
     *
     * CryptoUtil methods will be called to create the data to securely send the
     * passphrase to the DRM. Basically, three pieces of data will be sent:
     *
     * - the passphrase wrapped by a 168 bit 3DES symmetric key (the session key).
     * - the session key wrapped with the public key in the DRM transport certificate.
     * - an ivps vector to be used as nonceData.
     *
     * @param keyId -- key id of secret.
     * @param passphrase -- passphrase used to wrap the secret in the response.
     * @return A Key object with the secret wrapped with the passphrase.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public Key retrieveKeyByPassphrase(KeyId keyId, String passphrase) throws Exception {
        if (keyId == null) {
            throw new IllegalArgumentException("KeyId must be specified.");
        }
        if (passphrase == null) {
            throw new IllegalArgumentException("Passphrase must be specified.");
        }
        SymmetricKey sessionKey = crypto.generateSessionKey();
        byte[] transWrappedSessionKey = crypto.wrapSessionKeyWithTransportCert(sessionKey, this.transportCert);
        byte[] nonceData = CryptoUtil.getNonceData(8);
        byte[] sessionWrappedPassphrase = crypto.wrapWithSessionKey(passphrase, nonceData, sessionKey,
                KeyRequestResource.DES3_ALGORITHM);

        return retrieveKeyUsingWrappedPassphrase(keyId, transWrappedSessionKey, sessionWrappedPassphrase, nonceData);
    }

    /**
     *
     * This method generates a key recovery request, approves it, and retrieves
     * the secret referred to by keyId. This assumes that only one approval is required
     * to authorize the recovery.
     *
     * The method will return the secret encrypted by the passphrase using
     * PBE Encryption. The secret will still need to be decrypted by the caller.
     *
     * @param keyId -- key id for secret
     * @param transWrappedSessionKey -- Session key wrapped with the transport cert
     * @param sessionWrappedPassphrase -- Passphrase wrapped with the session key
     * @param nonceData -- nonce data used for encryption.
     * @return A Key object with the secret wrapped by the passphrase provided.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public Key retrieveKeyUsingWrappedPassphrase(KeyId keyId, byte[] transWrappedSessionKey,
            byte[] sessionWrappedPassphrase, byte[] nonceData) throws Exception {

        if (keyId == null) {
            throw new IllegalArgumentException("KeyId has to be specified.");
        }

        if (sessionWrappedPassphrase == null) {
            throw new IllegalArgumentException("Session key wrapped passphrase must be specified.");

        }
        if (transWrappedSessionKey == null || nonceData == null) {
            throw new IllegalArgumentException(
                    "No way to extract passphrase. Both transWrappedSessionKey and nonceData must be specified.");
        }

        // Need to pass the sessionWrappedPassphrase and transWrappedSessionKey when the
        // both request and recovery are done at the same time. So the KeyRequestResounse itself
        // contains the KeyData
        RequestId requestId = recoverKey(keyId, null, null, null, null).getRequestId();
        approveRequest(requestId);

        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(keyId);
        data.setRequestId(requestId);
        if (transWrappedSessionKey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey));
        }
        if (sessionWrappedPassphrase != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(sessionWrappedPassphrase));
        }
        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData));
        }

        // Just return the KeyData as the wrappedPrivateData contains the key wrapped by the passphrase
        // and the the nonceData, to recover extract the key.
        return retrieveKeyData(data);
    }

    /**
     * Retrieve an asymmetric private key and return it as PKCS12 data.
     *
     * This function generates a key recovery request, approves it, and retrieves
     * the secret referred to by key_id in a PKCS12 file. This assumes that only
     * one approval is required to authorize the recovery.
     *
     * @param keyId -- key id for secret
     * @param certificate -- the certificate associated with the private key
     * @param passphrase -- A passphrase for the pkcs12 file.
     * @return A Key object with the wrapped secret
     */
    public Key retrieveKeyByPKCS12(KeyId keyId, String certificate, String passphrase) {
        if (keyId == null || certificate == null || passphrase == null) {
            throw new IllegalArgumentException("KeyId, certificate and passphrase must be specified.");
        }
        KeyRequestResponse keyData = recoverKey(keyId, null, null, null, certificate);
        approveRequest(keyData.getRequestId());

        KeyRecoveryRequest recoveryRequest = new KeyRecoveryRequest();
        recoveryRequest.setKeyId(keyId);
        recoveryRequest.setRequestId(keyData.getRequestId());
        recoveryRequest.setPassphrase(passphrase);

        return retrieveKeyData(recoveryRequest);
    }

    /**
     * Archive a passphrase on the DRM.
     *
     * Requires a user-supplied client ID. There can be only one active
     * key with a specified client ID. If a record for a duplicate active
     * key exists, a BadRequestException is thrown.
     *
     *
     * @param clientKeyId -- Client Key Identfier
     * @param passphrase -- Secret passphrase to be archived
     * @return A KeyRequestResponse object with information about the request.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             IOException, CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyRequestResponse archivePassphrase(String clientKeyId, String passphrase) throws Exception {

        // Default algorithm OID for DES_EDE3_CBC
        String algorithmOID = EncryptionAlgorithm.DES3_CBC.toOID().toString();
        byte[] nonceData = CryptoUtil.getNonceData(8);
        SymmetricKey sessionKey = crypto.generateSessionKey();
        byte[] transWrappedSessionKey = crypto.wrapSessionKeyWithTransportCert(sessionKey, this.transportCert);
        byte[] encryptedData = crypto.wrapWithSessionKey(passphrase, nonceData,
                sessionKey, KeyRequestResource.DES3_ALGORITHM);

        return archiveEncryptedData(clientKeyId, KeyRequestResource.PASS_PHRASE_TYPE, null, 0, algorithmOID,
                nonceData, encryptedData, transWrappedSessionKey);
    }

    /**
     * Archive a symmetric key on the DRM.
     *
     * Requires a user-supplied client ID. There can be only one active
     * key with a specified client ID. If a record for a duplicate active
     * key exists, a BadRequestException is thrown.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param keyAlgorithm -- Algorithm used by the symmetric key
     * @param keySize -- Strength of the symmetric key (secret)
     * @return A KeyRequestResponse object with information about the request.
     * @throws Exception - Exceptions of type NoSuchAlgorithmException, IllegalStateException, TokenException,
     *             IOException, CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException,
     *             BadPaddingException, IllegalBlockSizeException
     */
    public KeyRequestResponse archiveSymmetricKey(String clientKeyId, SymmetricKey secret, String keyAlgorithm,
            int keySize) throws Exception {

        // Default algorithm OID for DES_EDE3_CBC
        String algorithmOID = EncryptionAlgorithm.DES3_CBC.toOID().toString();
        SymmetricKey sessionKey = crypto.generateSessionKey();
        byte[] nonceData = CryptoUtil.getNonceData(8);
        byte[] encryptedData = crypto.wrapWithSessionKey(secret, sessionKey, nonceData);
        byte[] transWrappedSessionKey = crypto.wrapSessionKeyWithTransportCert(sessionKey, this.transportCert);

        return archiveEncryptedData(clientKeyId, KeyRequestResource.SYMMETRIC_KEY_TYPE, keyAlgorithm, keySize,
                algorithmOID, nonceData, encryptedData, transWrappedSessionKey);
    }

    /**
     * Archive a secret (symmetric key or passphrase) on the DRM.
     *
     * This method is useful if the caller wants to do their own wrapping
     * of the secret, or if the secret was generated on a separate client
     * machine and the wrapping was done there.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param dataType -- Type of secret being archived
     * @param keyAlgorithm -- Algorithm used - if the secret is a symmetric key
     * @param keySize -- Strength of the symmetric key (secret)
     * @param algorithmOID -- OID of the algorithm used for the symmetric key wrap
     * @param symAlgParams -- storing the value of Utils.base64encode(nonceData)
     * @param encryptedData -- which is the secret wrapped by a session
     *            key (168 bit 3DES symmetric key)
     * @param transWrappedSessionKey -- session key wrapped by the transport cert.
     * @return A KeyRequestResponse object with information about the request.
     */
    public KeyRequestResponse archiveEncryptedData(String clientKeyId, String dataType, String keyAlgorithm,
            int keySize,
            String algorithmOID, byte[] nonceData, byte[] encryptedData, byte[] transWrappedSessionKey) {

        if (clientKeyId == null || dataType == null) {
            throw new IllegalArgumentException("Client key id and data type must be specified.");
        }
        if (dataType == KeyRequestResource.SYMMETRIC_KEY_TYPE) {
            if (keyAlgorithm == null || keySize < 0) {
                throw new IllegalArgumentException(
                        "Key algorithm and key size must be specified for a symmetric key type request.");
            }
        }
        if (encryptedData == null || transWrappedSessionKey == null || algorithmOID == null
                || nonceData == null) {
            throw new IllegalArgumentException("All data and wrapping parameters must be specified.");
        }
        KeyArchivalRequest data = new KeyArchivalRequest();

        data.setDataType(dataType);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(keySize);
        data.setClientKeyId(clientKeyId);
        data.setAlgorithmOID(algorithmOID);
        data.setSymmetricAlgorithmParams(Utils.base64encode(nonceData));
        String req1 = Utils.base64encode(encryptedData);
        data.setWrappedPrivateData(req1);
        data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey));

        return submitRequest(data);
    }

    /**
     * Archive a secret (symmetric key or passphrase) on the DRM using a PKIArchiveOptions data format.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param dataType -- Type of secret bring archived
     * @param keyAlgorithm -- Algorithm used if the secret is a symmetric key
     * @param keySize -- Strength of the symmetric key
     * @param pkiArchiveOptions -- is the data to be archived wrapped in a
     *            PKIArchiveOptions structure
     * @return A KeyRequestResponse object with information about the request.
     * @throws Exception
     */
    public KeyRequestResponse archivePKIOptions(String clientKeyId, String dataType, String keyAlgorithm, int keySize,
            byte[] pkiArchiveOptions) {

        if (clientKeyId == null || dataType == null) {
            throw new IllegalArgumentException("Client key id and data type must be specified.");
        }
        if (dataType == KeyRequestResource.SYMMETRIC_KEY_TYPE) {
            if (keyAlgorithm == null || keySize < 0) {
                throw new IllegalArgumentException(
                        "Key algorithm and key size must be specified for a symmetric key type request.");
            }
        }
        if (pkiArchiveOptions == null) {
            throw new IllegalArgumentException(
                    "No data provided to be archived. PKIArchiveOptions data must be specified.");
        }
        KeyArchivalRequest data = new KeyArchivalRequest();

        data.setClientKeyId(clientKeyId);
        data.setDataType(dataType);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(keySize);

        String options = Utils.base64encode(pkiArchiveOptions);
        data.setPKIArchiveOptions(options);

        return submitRequest(data);
    }

    /**
     * Generate and archive a symmetric key in the DRM.
     *
     * @param clientKeyId -- Client Key Identifier
     * @param keyAlgorithm -- Algorithm to be used to generate the key
     * @param keySize -- Strength of the keys
     * @param usages -- Usages of the generated key.
     * @return a KeyRequestResponse which contains a KeyRequestInfo
     *         object that describes the URL for the request and generated key.
     */
    public KeyRequestResponse generateSymmetricKey(String clientKeyId, String keyAlgorithm, int keySize,
            List<String> usages, String transWrappedSessionKey) {
        if (clientKeyId == null) {
            throw new IllegalArgumentException("Client Key Identifier must be specified.");
        }
        //Validate the usages list
        List<String> validUsages = SymKeyGenerationRequest.getValidUsagesList();
        if (usages != null) {
            for (String usage : usages) {
                if (!validUsages.contains(usage)) {
                    throw new IllegalArgumentException("Invalid usage \"" + usage + "\" specified.");
                }
            }
        }
        SymKeyGenerationRequest data = new SymKeyGenerationRequest();
        data.setClientKeyId(clientKeyId);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(new Integer(keySize));
        data.setUsages(usages);
        data.setTransWrappedSessionKey(transWrappedSessionKey);

        return submitRequest(data);
    }

    /**
     * Generate and archive an asymmetric keys in the DRM
     *
     * @param clientKeyId -- Client Key Identifier
     * @param keyAlgorithm -- Algorithm to be used to generate the asymmetric keys
     * @param keySize -- Strength of the keys
     * @param usages
     * @param transWrappedSessionKey
     * @return
     */
    public KeyRequestResponse generateAsymmetricKey(String clientKeyId, String keyAlgorithm, int keySize,
            List<String> usages, byte[] transWrappedSessionKey) {

        if (clientKeyId == null) {
            throw new IllegalArgumentException("Client Key Identifier must be specified.");
        }

        //Validate the usages list
        List<String> validUsages = AsymKeyGenerationRequest.getValidUsagesList();
        if (usages != null) {
            for (String usage : usages) {
                if (!validUsages.contains(usage)) {
                    throw new IllegalArgumentException("Invalid usage \"" + usage + "\" specified.");
                }
            }
        }
        if (!(keyAlgorithm.equals(KeyRequestResource.RSA_ALGORITHM) || keyAlgorithm
                .equals(KeyRequestResource.DSA_ALGORITHM))) {
            throw new IllegalArgumentException("Unsupported algorithm specified.");
        }

        /*
         * For RSA, JSS accepts key sizes that fall in this set of values:
         * {256 + (16 * n), where 0 <= n <= 1008
         *
         * For DSA, JSS accepts key sizes 512, 768, 1024 only, when there are no p,q,g params specified.
         */
        if (keyAlgorithm.equals(KeyRequestResource.RSA_ALGORITHM)) {
            if (keySize >= 256) {
                if ((keySize - 256) % 16 != 0) {
                    throw new IllegalArgumentException("Invalid key size specified.");
                }
            } else {
                throw new IllegalArgumentException("Invalid key size specified.");
            }
        } else if (keyAlgorithm.equals(KeyRequestResource.DSA_ALGORITHM)) {
            if (keySize != 512 && keySize != 768 && keySize != 1024) {
                throw new IllegalArgumentException("Invalid key size specified.");
            }
        }
        AsymKeyGenerationRequest data = new AsymKeyGenerationRequest();
        data.setClientKeyId(clientKeyId);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(keySize);
        data.setUsages(usages);
        data.setTransWrappedSessionKey(Utils.base64encode(transWrappedSessionKey));

        return submitRequest(data);
    }
}
