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
//(C) 2013 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging;

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AuditClient extends Client {

    public AuditClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "audit");
    }

    public AuditConfig getAuditConfig() throws Exception {
        return get(AuditConfig.class);
    }

    public AuditConfig updateAuditConfig(AuditConfig auditConfig) throws Exception {
        Entity<AuditConfig> entity = client.entity(auditConfig);
        return patch(null, null, entity, AuditConfig.class);
    }

    public AuditConfig changeAuditStatus(String action) throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("action", action);
        return post(null, params, null, AuditConfig.class);
    }

    public AuditFileCollection findAuditFiles() throws Exception {
        return get("files", AuditFileCollection.class);
    }

    public StreamingOutput getAuditFile(String filename) throws Exception {
        WebTarget target = target("files/" + filename, null);
        Response response = target.request(MediaType.APPLICATION_OCTET_STREAM).get();
        return client.getEntity(response, StreamingOutput.class);
    }
}
