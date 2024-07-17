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

import jakarta.ws.rs.client.Entity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;

/**
 * @author Endi S. Dewata
 */
public class CAAgentCertClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(CAAgentCertClient.class);

    public CAAgentCertClient(PKIClient client) throws Exception {
        super(client, "ca", "agent/certs");
    }

    public CertData reviewCert(CertId id) throws Exception {
        return get(id.toHexString(), CertData.class);
    }

    public CertRequestInfo revokeCert(CertId id, CertRevokeRequest request) throws Exception {
        Entity<CertRevokeRequest> entity = client.entity(request);
        return post(id.toHexString() + "/revoke", null, entity, CertRequestInfo.class);
    }

    public CertRequestInfo revokeCACert(CertId id, CertRevokeRequest request) throws Exception {
        Entity<CertRevokeRequest> entity = client.entity(request);
        return post(id.toHexString() + "/revoke-ca", null, entity, CertRequestInfo.class);
    }

    public CertRequestInfo unrevokeCert(CertId id) throws Exception {
        return post(id.toHexString() + "/unrevoke", CertRequestInfo.class);
    }
}
