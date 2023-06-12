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

import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertRequestResource;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.request.RequestId;

/**
 * @author Endi S. Dewata
 */
public class CACertRequestClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(CACertRequestClient.class);

    public CertRequestResource certRequestClient;

    public CACertRequestClient(PKIClient client) throws Exception {
        super(client, "ca", "certrequests");
        init();
    }

    public void init() throws Exception {
        certRequestClient = createProxy(CertRequestResource.class);
    }

    public CertRequestInfo getRequest(RequestId id) throws Exception {
        Response response = certRequestClient.getRequestInfo(id);
        return client.getEntity(response, CertRequestInfo.class);
    }

    public CertRequestInfos enrollRequest(
            CertEnrollmentRequest data, AuthorityID aid, X500Name adn) throws Exception {
        String aidString = aid != null ? aid.toString() : null;
        String adnString = adn != null ? adn.toLdapDNString() : null;
        String enrollmentRequest = (String) client.marshall(data);
        Response response = certRequestClient.enrollCert(enrollmentRequest, aidString, adnString);
        return client.getEntity(response, CertRequestInfos.class);
    }

    public ProfileDataInfos listEnrollmentTemplates(Integer start, Integer size) throws Exception {
        Response response = certRequestClient.listEnrollmentTemplates(start, size);
        return client.getEntity(response, ProfileDataInfos.class);
    }

    public CertEnrollmentRequest getEnrollmentTemplate(String id) throws Exception {
        Response response = certRequestClient.getEnrollmentTemplate(id);
        return client.getEntity(response, CertEnrollmentRequest.class);
    }
}
