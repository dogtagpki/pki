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
package com.netscape.cms.client.cert;

import java.net.URISyntaxException;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.client.cli.ClientConfig;
import com.netscape.cms.servlet.cert.CertResource;
import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertRevokeRequest;
import com.netscape.cms.servlet.cert.model.CertSearchData;
import com.netscape.cms.servlet.cert.model.CertUnrevokeRequest;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.csadmin.CMSRestClient;
import com.netscape.cms.servlet.request.CertRequestResource;
import com.netscape.cms.servlet.request.model.AgentEnrollmentRequestData;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRequestInfos;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;

/**
 * @author Endi S. Dewata
 */
public class CertRestClient extends CMSRestClient {

    public CertResource certClient;
    public CertRequestResource certRequestResource;

    public CertRestClient(ClientConfig config) throws URISyntaxException {
        super(config);

        certClient = createProxy(CertResource.class);
        certRequestResource = createProxy(CertRequestResource.class);
    }

    public CertificateData getCert(CertId id) {
        return certClient.getCert(id);
    }

    public CertDataInfos findCerts(CertSearchData data, Integer start, Integer size) {
        return certClient.searchCerts(data, start, size);
    }

    public CertRequestInfo revokeCert(CertId id, CertRevokeRequest request) {
        return certClient.revokeCert(id, request);
    }

    public CertRequestInfo revokeCACert(CertId id, CertRevokeRequest request) {
        return certClient.revokeCACert(id, request);
    }

    public CertRequestInfo unrevokeCert(CertId id, CertUnrevokeRequest request) {
        return certClient.unrevokeCert(id, request);
    }

    public CertRequestInfos enrollRequest(EnrollmentRequestData data){
        return certRequestResource.enrollCert(data);
    }

    public AgentEnrollmentRequestData reviewRequest(RequestId id){
        return certRequestResource.reviewRequest(id);
    }

    public void approveRequest(RequestId id, AgentEnrollmentRequestData data) {
        certRequestResource.approveRequest(id, data);
    }
}
