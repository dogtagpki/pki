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

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.cert.CertResource;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.cert.CertUnrevokeRequest;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.client.ClientConfig;
import com.netscape.cms.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class CertClient extends PKIClient {

    public CertResource certClient;
    public CertRequestResource certRequestResource;

    public CertClient(ClientConfig config) throws URISyntaxException {
        super(config);

        certClient = createProxy(CertResource.class);
        certRequestResource = createProxy(CertRequestResource.class);
    }

    public CertData getCert(CertId id) {
        return certClient.getCert(id);
    }

    public CertDataInfos findCerts(CertSearchRequest data, Integer start, Integer size) {
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

    public CertRequestInfos enrollRequest(CertEnrollmentRequest data) {
        return certRequestResource.enrollCert(data);
    }

    public CertReviewResponse reviewRequest(RequestId id) {
        return certRequestResource.reviewRequest(id);
    }

    public void approveRequest(RequestId id, CertReviewResponse data) {
        certRequestResource.approveRequest(id, data);
    }
}
