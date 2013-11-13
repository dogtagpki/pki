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

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.request.RequestId;

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

    public KeyDataInfos findKeys(String clientID, String status, Integer maxSize, Integer maxTime,
            Integer start, Integer size) {
        return keyClient.listKeys(clientID, status, maxSize, maxTime, start, size);
    }

    public KeyData retrieveKey(KeyRecoveryRequest data) {
        return keyClient.retrieveKey(data);
    }

    public KeyRequestInfos findKeyRequests(
            String requestState,
            String requestType,
            String clientID,
            RequestId start,
            Integer pageSize,
            Integer maxResults,
            Integer maxTime) {
        return keyRequestClient.listRequests(
                requestState,
                requestType,
                clientID,
                start,
                pageSize,
                maxResults,
                maxTime);
    }
}
