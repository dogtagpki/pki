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
//(C) 2015 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.authority;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;

import com.netscape.certsrv.base.ClientConnectionException;
import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * @author Fraser Tweedale &lt;ftweedal@redhat.com&gt;
 */
public class AuthorityClient extends Client {

    public AuthorityClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.getName());
    }

    public AuthorityClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "authorities");
    }

    public Collection<AuthorityData> listCAs() throws Exception {
        return findCAs(null, null, null, null);
    }

    public Collection<AuthorityData> findCAs(String id, String parentID, String dn, String issuerDN) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (id != null) params.put("id", id);
        if (parentID != null) params.put("parentID", parentID);
        if (dn != null) params.put("dn", dn);
        if (issuerDN != null) params.put("issuerDN", issuerDN);
        return getCollection(null, params, AuthorityData.class);
    }

    public AuthorityData getCA(String caIDString) throws Exception {
        return get(caIDString, AuthorityData.class);
    }

    public String getChainPEM(String caIDString) throws Exception {
        URIBuilder target = target(caIDString + "/chain", null);
        HttpGet httpGET = new HttpGet(target.build());
        httpGET.addHeader(HttpHeaders.ACCEPT, MimeType.APPLICATION_X_PEM_FILE);
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = client.getConnection().getHttpClient().execute(httpGET);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return client.getEntity(httpResp, String.class);
    }

    public AuthorityData createCA(AuthorityData data) throws Exception {
        HttpEntity entity = client.entity(data);
        return post(null, null, entity, AuthorityData.class);
    }

    public AuthorityData modifyCA(AuthorityData data) throws Exception {
        HttpEntity entity = client.entity(data);
        return put(data.getID(), null, entity, AuthorityData.class);
    }

    public void deleteCA(String aidString) throws Exception {
        delete(aidString, Void.class);
    }

}
