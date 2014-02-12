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
package com.netscape.certsrv.cert;

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.request.RequestId;

/**
 * @author Endi S. Dewata
 */
public class CertClient extends Client {

    public CertResource certClient;
    public CertRequestResource certRequestClient;

    public CertClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "cert");
        init();
    }

    public void init() throws URISyntaxException {
        certClient = createProxy(CertResource.class);
        certRequestClient = createProxy(CertRequestResource.class);
    }

    public CertData getCert(CertId id) {
        Response response = certClient.getCert(id);
        return client.getEntity(response, CertData.class);
    }

    public CertData reviewCert(CertId id) {
        Response response = certClient.reviewCert(id);
        return client.getEntity(response, CertData.class);
    }

    public CertDataInfos listCerts(String status, Integer maxResults, Integer maxTime, Integer start, Integer size) {
        Response response = certClient.listCerts(status, maxResults, maxTime, start, size);
        return client.getEntity(response, CertDataInfos.class);
    }

    public CertDataInfos findCerts(CertSearchRequest data, Integer start, Integer size) {
        Response response = certClient.searchCerts(data, start, size);
        return client.getEntity(response, CertDataInfos.class);
    }

    public CertRequestInfo revokeCert(CertId id, CertRevokeRequest request) {
        Response response = certClient.revokeCert(id, request);
        return client.getEntity(response, CertRequestInfo.class);
    }

    public CertRequestInfo revokeCACert(CertId id, CertRevokeRequest request) {
        Response response = certClient.revokeCACert(id, request);
        return client.getEntity(response, CertRequestInfo.class);
    }

    public CertRequestInfo unrevokeCert(CertId id, CertUnrevokeRequest request) {
        Response response = certClient.unrevokeCert(id, request);
        return client.getEntity(response, CertRequestInfo.class);
    }

    public CertRequestInfos enrollRequest(CertEnrollmentRequest data) {
        Response response = certRequestClient.enrollCert(data);
        return client.getEntity(response, CertRequestInfos.class);
    }

    public CertRequestInfo getRequest(RequestId id) {
        Response response = certRequestClient.getRequestInfo(id);
        return client.getEntity(response, CertRequestInfo.class);
    }

    public CertReviewResponse reviewRequest(RequestId id) {
        Response response = certRequestClient.reviewRequest(id);
        return client.getEntity(response, CertReviewResponse.class);
    }

    public void approveRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.approveRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void rejectRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.rejectRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void cancelRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.cancelRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void updateRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.updateRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void validateRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.validateRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void assignRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.assignRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public void unassignRequest(RequestId id, CertReviewResponse data) {
        Response response = certRequestClient.unassignRequest(id, data);
        client.getEntity(response, Void.class);
    }

    public CertRequestInfos listRequests(String requestState, String requestType, RequestId start, Integer pageSize,
            Integer maxResults, Integer maxTime) {
        Response response = certRequestClient.listRequests(requestState, requestType, start, pageSize, maxResults, maxTime);
        return client.getEntity(response, CertRequestInfos.class);
    }

    public CertEnrollmentRequest getEnrollmentTemplate(String id) {
        Response response = certRequestClient.getEnrollmentTemplate(id);
        return client.getEntity(response, CertEnrollmentRequest.class);
    }

    public ProfileDataInfos listEnrollmentTemplates(Integer start, Integer size) {
        Response response = certRequestClient.listEnrollmentTemplates(start, size);
        return client.getEntity(response, ProfileDataInfos.class);
    }
}
