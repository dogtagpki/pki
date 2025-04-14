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
package com.netscape.certsrv.ca;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.request.RequestId;

/**
 * @author Endi S. Dewata
 */
public class CAAgentCertRequestClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(CAAgentCertRequestClient.class);

    public CAAgentCertRequestClient(PKIClient client) throws Exception {
        super(client, "ca", "agent/certrequests");
    }

    public CertRequestInfos listRequests(String requestState, String requestType, String start, Integer pageSize,
            Integer maxResults, Integer maxTime) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (requestType != null) params.put("requestType", requestType);
        if (start != null) params.put("start", start);
        if (pageSize != null) params.put("pageSize", pageSize);
        if (maxResults != null) params.put("maxResults", maxResults);
        if (maxTime != null) params.put("maxTime", maxTime);
        return get(null, params, CertRequestInfos.class);
    }

    public CertReviewResponse reviewRequest(RequestId id) throws Exception {
        return get(id.toHexString(), CertReviewResponse.class);
    }

    public void approveRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/approve", null, entity, Void.class);
    }

    public void rejectRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/reject", null, entity, Void.class);
    }

    public void cancelRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/cancel", null, entity, Void.class);
    }

    public void updateRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/update", null, entity, Void.class);
    }

    public void validateRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/validate", null, entity, Void.class);
    }

    public void assignRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/assign", null, entity, Void.class);
    }

    public void unassignRequest(RequestId id, CertReviewResponse data) throws Exception {
        HttpEntity entity = client.entity(data);
        post(id.toHexString() + "/unassign", null, entity, Void.class);
    }
}
