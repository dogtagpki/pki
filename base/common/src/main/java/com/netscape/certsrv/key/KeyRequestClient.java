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

import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.request.RequestId;

/**
 * @author Endi S. Dewata
 * @author Abhishek Koneru
 */
public class KeyRequestClient extends Client {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyRequestClient.class);

    public KeyRequestResource keyRequestClient;

    public KeyRequestClient(PKIClient client) throws Exception {
        super(client, "kra", "agent/keyrequests");
        init();
    }

    public void init() throws Exception {
        keyRequestClient = createProxy(KeyRequestResource.class);
    }

    /**
     * Search key requests in the DRM based on the state/type of the requests.
     *
     * @param requestState -- State of the requests to be queried.
     * @param requestType -- Type of the requests to be queried.
     * @param realm   -- Authz Realm
     * @return a KeyRequestCollection object.
     */
    public KeyRequestInfoCollection listRequests(String requestState, String requestType, String realm) throws Exception {
        return listRequests(
                requestState,
                requestType,
                null,
                new RequestId(0),
                100,
                100,
                10,
                realm);
    }

    /* method for backwards compatibility */
    public KeyRequestInfoCollection listRequests(String requestState, String requestType) throws Exception {
        return listRequests(
                requestState,
                requestType,
                null,
                new RequestId(0),
                100,
                100,
                10,
                null);
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
     * @param realm -- Authz Realm
     * @return a KeyRequestInfoCollection object.
     */
    public KeyRequestInfoCollection listRequests(
            String requestState,
            String requestType,
            String clientKeyID,
            RequestId start,
            Integer pageSize,
            Integer maxResults,
            Integer maxTime,
            String realm) throws Exception {
        Response response = keyRequestClient.listRequests(
                requestState,
                requestType,
                clientKeyID,
                start,
                pageSize,
                maxResults,
                maxTime,
                realm);
        return client.getEntity(response, KeyRequestInfoCollection.class);
    }

    /**
     * Return a KeyRequestInfo object for a specific request.
     *
     * @param id -- A Request Id object
     * @return the KeyRequestInfo object for a specific request.
     */
    public KeyRequestInfo getRequestInfo(RequestId id) throws Exception {
        if (id == null) {
            throw new IllegalArgumentException("Request Id must be specified.");
        }
        Response response = keyRequestClient.getRequestInfo(id);
        return client.getEntity(response, KeyRequestInfo.class);
    }

    /**
     * Approve a secret recovery request
     *
     * @param id -- Id of the request
     */
    public void approveRequest(RequestId id) throws Exception {
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
    public void rejectRequest(RequestId id) throws Exception {
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
    public void cancelRequest(RequestId id) throws Exception {
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
    KeyRequestResponse submitRequest(RESTMessage request) throws Exception {

        if (request == null) {
            throw new IllegalArgumentException("A Request object must be specified.");
        }

        logger.info("Submitting " + request.getClassName() + " to KRA");

        Response response = keyRequestClient.submitRequest(request);
        return client.getEntity(response, KeyRequestResponse.class);
    }
}
