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

import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.AgentCertRequestResource;
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

    public AgentCertRequestResource agentCertRequestClient;

    public CAAgentCertRequestClient(PKIClient client) throws Exception {
        super(client, "ca", "agent/certrequests");
        init();
    }

    public CertRequestInfos listRequests(String requestState, String requestType, RequestId start, Integer pageSize,
            Integer maxResults, Integer maxTime) throws Exception {
        Response response = agentCertRequestClient.listRequests(requestState, requestType, start, pageSize, maxResults, maxTime);
        return client.getEntity(response, CertRequestInfos.class);
    }

    public void init() throws Exception {
        agentCertRequestClient = createProxy(AgentCertRequestResource.class);
    }

    public CertReviewResponse reviewRequest(RequestId id) throws Exception {
        Response response = agentCertRequestClient.reviewRequest(id);
        return client.getEntity(response, CertReviewResponse.class);
    }

    public void approveRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.approveRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void rejectRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.rejectRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void cancelRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.cancelRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void updateRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.updateRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void validateRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.validateRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void assignRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.assignRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void unassignRequest(RequestId id, CertReviewResponse data) throws Exception {
        Response response = agentCertRequestClient.unassignRequest(id, data);
        client.getEntity(response, Void.class);
    }
}
