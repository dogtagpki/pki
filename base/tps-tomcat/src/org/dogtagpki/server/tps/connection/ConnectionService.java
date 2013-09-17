// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.connection;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.connection.ConnectionCollection;
import com.netscape.certsrv.tps.connection.ConnectionData;
import com.netscape.certsrv.tps.connection.ConnectionInfo;
import com.netscape.certsrv.tps.connection.ConnectionModification;
import com.netscape.certsrv.tps.connection.ConnectionResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ConnectionService extends PKIService implements ConnectionResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public ConnectionService() {
        CMS.debug("ConnectionService.<init>()");
    }

    public ConnectionInfo createConnectionInfo(ConnectionRecord connectionRecord) {

        ConnectionInfo connectionInfo = new ConnectionInfo();
        connectionInfo.setID(connectionRecord.getID());
        connectionInfo.setStatus(connectionRecord.getStatus());

        String connectionID = connectionRecord.getID();
        try {
            connectionID = URLEncoder.encode(connectionID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(ConnectionResource.class).path("{connectionID}").build(connectionID);
        connectionInfo.setLink(new Link("self", uri));

        return connectionInfo;
    }

    public ConnectionData createConnectionData(ConnectionRecord connectionRecord) {

        ConnectionData connectionData = new ConnectionData();
        connectionData.setID(connectionRecord.getID());
        connectionData.setStatus(connectionRecord.getStatus());
        connectionData.setContents(connectionRecord.getContents());

        String connectionID = connectionRecord.getID();
        try {
            connectionID = URLEncoder.encode(connectionID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }

        URI uri = uriInfo.getBaseUriBuilder().path(ConnectionResource.class).path("{connectionID}").build(connectionID);
        connectionData.setLink(new Link("self", uri));

        return connectionData;
    }

    public ConnectionRecord createConnectionRecord(ConnectionData connectionData) {

        ConnectionRecord connectionRecord = new ConnectionRecord();
        connectionRecord.setID(connectionData.getID());
        connectionRecord.setStatus(connectionData.getStatus());
        connectionRecord.setContents(connectionData.getContents());

        return connectionRecord;
    }

    @Override
    public ConnectionCollection findConnections(Integer start, Integer size) {

        CMS.debug("ConnectionService.findConnections()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            Iterator<ConnectionRecord> connections = database.getRecords().iterator();

            ConnectionCollection response = new ConnectionCollection();

            int i = 0;

            // skip to the start of the page
            for ( ; i<start && connections.hasNext(); i++) connections.next();

            // return entries up to the page size
            for ( ; i<start+size && connections.hasNext(); i++) {
                response.addEntry(createConnectionInfo(connections.next()));
            }

            // count the total entries
            for ( ; connections.hasNext(); i++) connections.next();

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public ConnectionData getConnection(String connectionID) {

        CMS.debug("ConnectionService.getConnection(\"" + connectionID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            return createConnectionData(database.getRecord(connectionID));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addConnection(ConnectionData connectionData) {

        CMS.debug("ConnectionService.addConnection(\"" + connectionData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            database.addRecord(createConnectionRecord(connectionData));
            connectionData = createConnectionData(database.getRecord(connectionData.getID()));

            return Response
                    .created(connectionData.getLink().getHref())
                    .entity(connectionData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateConnection(String connectionID, ConnectionData connectionData) {

        CMS.debug("ConnectionService.updateConnection(\"" + connectionID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            database.updateRecord(createConnectionRecord(connectionData));
            connectionData = createConnectionData(database.getRecord(connectionID));

            return Response
                    .ok(connectionData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response modifyConnection(String connectionID, ConnectionModification request) {

        CMS.debug("ConnectionService.modifyConnection(\"" + connectionID + "\", request");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            ConnectionRecord connectionRecord = database.getRecord(connectionID);

            String status = request.getStatus();
            if (status != null) {
                connectionRecord.setStatus(status);
            }

            String contents = request.getContents();
            if (contents != null) {
                connectionRecord.setContents(contents);
            }

            database.updateRecord(connectionRecord);
            ConnectionData connectionData = createConnectionData(database.getRecord(connectionID));

            return Response
                    .ok(connectionData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void removeConnection(String connectionID) {

        CMS.debug("ConnectionService.removeConnection(\"" + connectionID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();
            database.removeRecord(connectionID);

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
