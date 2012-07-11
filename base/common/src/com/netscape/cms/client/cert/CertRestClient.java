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
import com.netscape.cms.servlet.cert.CertResource;
import com.netscape.cms.servlet.cert.CertsResource;
import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertRevokeRequest;
import com.netscape.cms.servlet.cert.model.CertSearchData;
import com.netscape.cms.servlet.cert.model.CertUnrevokeRequest;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.csadmin.CMSRestClient;
import com.netscape.cms.servlet.request.model.CertRequestInfo;

/**
 * @author Endi S. Dewata
 */
public class CertRestClient extends CMSRestClient {

    public CertResource certClient;
    public CertsResource certsClient;

    public CertRestClient(String baseUri) throws URISyntaxException {
        this(baseUri, null);
    }

    public CertRestClient(String baseUri, String nickname) throws URISyntaxException {
        super(baseUri, nickname);

        certClient = createProxy(CertResource.class);
        certsClient = createProxy(CertsResource.class);
    }

    public CertificateData getCert(CertId id) {
        return certClient.getCert(id);
    }

    public CertDataInfos findCerts(CertSearchData searchData) {
        return certsClient.searchCerts(
                searchData,
                CertsResource.DEFAULT_MAXRESULTS,
                CertsResource.DEFAULT_MAXTIME);
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
}
