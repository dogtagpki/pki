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

import com.netscape.certsrv.base.ResourceMessage;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmsutil.util.Utils;

/**
 * @author Endi S. Dewata
 */
public class KeyClient extends Client {

    public KeyResource keyClient;
    public KeyRequestResource keyRequestClient;

    public KeyClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "key");
        init();
    }

    public void init() throws URISyntaxException {
        keyClient = createProxy(KeyResource.class);
        keyRequestClient = createProxy(KeyRequestResource.class);
    }

    public KeyInfoCollection findKeys(String clientKeyID, String status, Integer maxSize, Integer maxTime,
            Integer start, Integer size) {
        Response response = keyClient.listKeys(clientKeyID, status, maxSize, maxTime, start, size);
        return client.getEntity(response, KeyInfoCollection.class);
    }

    public KeyInfo getActiveKeyInfo(String clientKeyID) {
        Response response = keyClient.getActiveKeyInfo(clientKeyID);
        return client.getEntity(response, KeyInfo.class);
    }

    public KeyData retrieveKey(KeyId keyId, RequestId requestId, byte[] rpwd, byte[] rkey, byte[] nonceData) {
        // create recovery request
        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(keyId);
        data.setRequestId(requestId);
        if (rkey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(rkey));
        }
        if (rpwd != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(rpwd));
        }

        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData));
        }

        return retrieveKey(data);
    }

    public KeyData retrieveKey(KeyRecoveryRequest data) {
        Response response = keyClient.retrieveKey(data);
        return client.getEntity(response, KeyData.class);
    }

    public KeyRequestInfoCollection findRequests(String requestState, String requestType) {
        return findRequests(
                requestState,
                requestType,
                null,
                new RequestId(0),
                100,
                100,
                10
        );
    }

    public KeyRequestInfoCollection findRequests(
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

    public KeyRequestInfo getRequestInfo(RequestId id) {
        Response response = keyRequestClient.getRequestInfo(id);
        return client.getEntity(response, KeyRequestInfo.class);
    }

    public KeyRequestResponse archiveSecurityData(String clientKeyId, String dataType,
            String algorithm, int strength, byte[] pkiArchiveOptions) {
        // create archival request
        KeyArchivalRequest data = new KeyArchivalRequest();
        data.setPKIArchiveOptions(Utils.base64encode(pkiArchiveOptions));
        data.setClientKeyId(clientKeyId);
        data.setDataType(dataType);
        data.setKeyAlgorithm(algorithm);
        data.setKeySize(strength);

        return createRequest(data);
    }

    public KeyRequestResponse archiveSecurityData(String clientKeyId, String dataType,
            String algorithm, int strength, byte[] wrappedPrivateData,
            byte[] wrappedSessionKey, String algorithmOID, byte[] algParams) {
        // create archival request
        KeyArchivalRequest data = new KeyArchivalRequest();
        data.setTransWrappedSessionKey(Utils.base64encode(wrappedSessionKey));
        data.setWrappedPrivateData(Utils.base64encode(wrappedPrivateData));
        data.setAlgorithmOID(algorithmOID);
        data.setSymmetricAlgorithmParams(Utils.base64encode(algParams));
        data.setClientKeyId(clientKeyId);
        data.setDataType(dataType);
        data.setKeyAlgorithm(algorithm);
        data.setKeySize(strength);

        return createRequest(data);
    }

    public KeyRequestResponse requestRecovery(KeyId keyId, byte[] rpwd, byte[] rkey, byte[] nonceData) {
        // create recovery request
        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(keyId);
        if (rpwd != null) {
            data.setSessionWrappedPassphrase(Utils.base64encode(rpwd));
        }
        if (rkey != null) {
            data.setTransWrappedSessionKey(Utils.base64encode(rkey));
        }

        if (nonceData != null) {
            data.setNonceData(Utils.base64encode(nonceData));
        }

        return createRequest(data);
    }

    public KeyRequestResponse requestKeyRecovery(String keyId, String b64Certificate) {
        // create key recovery request
        KeyRecoveryRequest data = new KeyRecoveryRequest();
        data.setKeyId(new KeyId(keyId));
        data.setCertificate(b64Certificate);

        return createRequest(data);
    }

    public KeyRequestResponse generateKey(String clientKeyId, String keyAlgorithm, int keySize, List<String> usages) {
        SymKeyGenerationRequest data = new SymKeyGenerationRequest();
        data.setClientKeyId(clientKeyId);
        data.setKeyAlgorithm(keyAlgorithm);
        data.setKeySize(new Integer(keySize));
        data.setUsages(usages);

        return createRequest(data);
    }

    public KeyRequestResponse createRequest(ResourceMessage data) {
        Response response = keyRequestClient.createRequest(data);
        return client.getEntity(response, KeyRequestResponse.class);
    }

    public void approveRequest(RequestId id) {
        Response response = keyRequestClient.approveRequest(id);
        client.getEntity(response, Void.class);
    }

    public void rejectRequest(RequestId id) {
        Response response = keyRequestClient.rejectRequest(id);
        client.getEntity(response, Void.class);
    }

    public void cancelRequest(RequestId id) {
        Response response = keyRequestClient.cancelRequest(id);
        client.getEntity(response, Void.class);
    }

    public KeyInfo getKeyInfo(KeyId id) {
        Response response = keyClient.getKeyInfo(id);
        return client.getEntity(response, KeyInfo.class);
    }

    public void modifyKeyStatus(KeyId id, String status) {
        Response response  = keyClient.modifyKeyStatus(id, status);
        client.getEntity(response, Void.class);
    }
}
