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
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.connection.ConnectionCollection;
import com.netscape.certsrv.tps.connection.ConnectionData;
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

    public ConnectionData createConnectionData(ConnectionRecord connectionRecord) throws UnsupportedEncodingException {

        String connectionID = connectionRecord.getID();

        ConnectionData connectionData = new ConnectionData();
        connectionData.setID(connectionID);
        connectionData.setStatus(connectionRecord.getStatus());
        connectionData.setProperties(connectionRecord.getProperties());

        connectionID = URLEncoder.encode(connectionID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(ConnectionResource.class).path("{connectionID}").build(connectionID);
        connectionData.setLink(new Link("self", uri));

        return connectionData;
    }

    public ConnectionRecord createConnectionRecord(ConnectionData connectionData) {

        ConnectionRecord connectionRecord = new ConnectionRecord();
        connectionRecord.setID(connectionData.getID());
        connectionRecord.setStatus(connectionData.getStatus());
        connectionRecord.setProperties(connectionData.getProperties());

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
                response.addEntry(createConnectionData(connections.next()));
            }

            // count the total entries
            for ( ; connections.hasNext(); i++) connections.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public ConnectionData getConnection(String connectionID) {

        if (connectionID == null) throw new BadRequestException("Connection ID is null.");

        CMS.debug("ConnectionService.getConnection(\"" + connectionID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            return createConnectionData(database.getRecord(connectionID));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addConnection(ConnectionData connectionData) {

        if (connectionData == null) throw new BadRequestException("Connection data is null.");

        CMS.debug("ConnectionService.addConnection(\"" + connectionData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            database.addRecord(connectionData.getID(), createConnectionRecord(connectionData));
            connectionData = createConnectionData(database.getRecord(connectionData.getID()));

            return Response
                    .created(connectionData.getLink().getHref())
                    .entity(connectionData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateConnection(String connectionID, ConnectionData connectionData) {

        if (connectionID == null) throw new BadRequestException("Connection ID is null.");
        if (connectionData == null) throw new BadRequestException("Connection data is null.");

        CMS.debug("ConnectionService.updateConnection(\"" + connectionID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();

            database.updateRecord(connectionData.getID(), createConnectionRecord(connectionData));
            connectionData = createConnectionData(database.getRecord(connectionID));

            return Response
                    .ok(connectionData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void removeConnection(String connectionID) {

        if (connectionID == null) throw new BadRequestException("Connection ID is null.");

        CMS.debug("ConnectionService.removeConnection(\"" + connectionID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectionDatabase database = subsystem.getConnectionDatabase();
            database.removeRecord(connectionID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
