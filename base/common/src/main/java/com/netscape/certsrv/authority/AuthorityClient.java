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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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

    public List<AuthorityData> listCAs() throws Exception {
        return findCAs(null, null, null, null);
    }

    public List<AuthorityData> findCAs(String id, String parentID, String dn, String issuerDN) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (id != null) params.put("id", id);
        if (parentID != null) params.put("parentID", parentID);
        if (dn != null) params.put("dn", dn);
        if (issuerDN != null) params.put("issuerDN", issuerDN);
        GenericType<List<AuthorityData>> type = new GenericType<>() {};
        return get(null, params, type);
    }

    public AuthorityData getCA(String caIDString) throws Exception {
        return get(caIDString, AuthorityData.class);
    }

    public String getChainPEM(String caIDString) throws Exception {
        WebTarget target = target(caIDString + "/chain", null);
        MediaType mediaType = MediaType.valueOf("application/x-pem-file");
        Response response = target.request(mediaType).get();
        return client.getEntity(response, String.class);
    }

    public AuthorityData createCA(AuthorityData data) throws Exception {
        Entity<AuthorityData> entity = client.entity(data);
        return post(null, null, entity, AuthorityData.class);
    }

    public AuthorityData modifyCA(AuthorityData data) throws Exception {
        Entity<AuthorityData> entity = client.entity(data);
        return put(data.getID(), null, entity, AuthorityData.class);
    }

    public void deleteCA(String aidString) throws Exception {
        delete(aidString, Void.class);
    }

}
