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
package com.netscape.cms.servlet.test;

import java.net.URISyntaxException;
import java.util.Collection;

import org.jboss.resteasy.client.ProxyFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.cert.CertResource;
import com.netscape.cms.servlet.cert.CertsResource;
import com.netscape.cms.servlet.cert.model.CertDataInfos;
import com.netscape.cms.servlet.cert.model.CertSearchData;
import com.netscape.cms.servlet.cert.model.CertificateData;
import com.netscape.cms.servlet.csadmin.CMSRestClient;
import com.netscape.cms.servlet.profile.ProfileResource;
import com.netscape.cms.servlet.profile.ProfilesResource;
import com.netscape.cms.servlet.profile.model.ProfileData;
import com.netscape.cms.servlet.profile.model.ProfileDataInfos;
import com.netscape.cms.servlet.request.CertRequestResource;
import com.netscape.cms.servlet.request.CertRequestsResource;
import com.netscape.cms.servlet.request.model.CertRequestInfo;
import com.netscape.cms.servlet.request.model.CertRequestInfos;
import com.netscape.cms.servlet.request.model.EnrollmentRequestData;

public class CARestClient extends CMSRestClient {

    private CertResource certClient;
    private CertsResource certsClient;
    private CertRequestsResource certRequestsClient;
    private CertRequestResource certRequestClient;
    private ProfilesResource profilesClient;
    private ProfileResource profileClient;

    public CARestClient(String baseUri, String clientCertNick) throws URISyntaxException {

        super(baseUri, clientCertNick);

        certRequestsClient = ProxyFactory.create(CertRequestsResource.class, uri, executor, providerFactory);
        certRequestClient = ProxyFactory.create(CertRequestResource.class, uri, executor, providerFactory);

        certsClient = ProxyFactory.create(CertsResource.class, uri, executor, providerFactory);
        certClient = ProxyFactory.create(CertResource.class, uri, executor, providerFactory);
        profilesClient = ProxyFactory.create(ProfilesResource.class, uri, executor, providerFactory);
        profileClient = ProxyFactory.create(ProfileResource.class, uri, executor, providerFactory);
    }

    public Collection<CertRequestInfo> listRequests(String requestState, String requestType) {

        CertRequestInfos infos = null;
        Collection<CertRequestInfo> list = null;
        infos = certRequestsClient.listRequests(
                requestState, requestType, new RequestId(0), 100, 100, 10);
        list = infos.getRequests();

        return list;
    }

    public CertDataInfos listCerts(String status) {
        return certsClient.listCerts(status, 100, 10);
    }

    public CertDataInfos searchCerts(CertSearchData data) {
        return certsClient.searchCerts(data, 100, 10);
    }

    public ProfileDataInfos listProfiles() {
        return profilesClient.listProfiles();
    }

    public ProfileData getProfile(String id) {

        if (id == null) {
            return null;
        }

        return profileClient.retrieveProfile(id);
    }

    public CertificateData getCertData(CertId id) {

        if (id == null) {
            return null;
        }

        return certClient.retrieveCert(id);

    }

    public CertRequestInfo enrollCertificate(EnrollmentRequestData data) {

        if (data == null) {
            return null;
        }
        return certRequestClient.enrollCert(data);
    }

    public CertRequestInfo getRequest(RequestId id) {

        if (id == null) {
            return null;
        }
        return certRequestClient.getRequestInfo(id);
    }

}
