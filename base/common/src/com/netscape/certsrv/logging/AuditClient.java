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

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class AuditClient extends Client {

    public AuditResource resource;

    public AuditClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "audit");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(AuditResource.class);
    }

    public AuditConfig getAuditConfig() {
        Response response = resource.getAuditConfig();
        return client.getEntity(response, AuditConfig.class);
    }

    public AuditConfig updateAuditConfig(AuditConfig auditConfig) {
        Response response = resource.updateAuditConfig(auditConfig);
        return client.getEntity(response, AuditConfig.class);
    }

    public AuditConfig changeAuditStatus(String action) {
        Response response = resource.changeAuditStatus(action);
        return client.getEntity(response, AuditConfig.class);
    }

    public AuditFileCollection findAuditFiles() {
        Response response = resource.findAuditFiles();
        return client.getEntity(response, AuditFileCollection.class);
    }

    public StreamingOutput getAuditFile(String filename) throws Exception {
        Response response = resource.getAuditFile(filename);
        return client.getEntity(response, StreamingOutput.class);
    }

    public void removeAuditFile(String filename) {
        Response response = resource.removeAuditFile(filename);
        client.getEntity(response, Void.class);
    }

    public StreamingOutput findAuditLogs(AuditLogFindRequest request) throws Exception {
        Response response = resource.findAuditLogs(request);
        return client.getEntity(response, StreamingOutput.class);
    }
}
