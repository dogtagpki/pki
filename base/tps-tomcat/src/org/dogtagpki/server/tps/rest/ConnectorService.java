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

package org.dogtagpki.server.tps.rest;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ConnectorDatabase;
import org.dogtagpki.server.tps.config.ConnectorRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.connector.ConnectorCollection;
import com.netscape.certsrv.tps.connector.ConnectorData;
import com.netscape.certsrv.tps.connector.ConnectorResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class ConnectorService extends PKIService implements ConnectorResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public ConnectorService() {
        CMS.debug("ConnectorService.<init>()");
    }

    public ConnectorData createConnectorData(ConnectorRecord connectionRecord) throws UnsupportedEncodingException {

        String connectorID = connectionRecord.getID();

        ConnectorData connectorData = new ConnectorData();
        connectorData.setID(connectorID);
        connectorData.setStatus(connectionRecord.getStatus());
        connectorData.setProperties(connectionRecord.getProperties());

        connectorID = URLEncoder.encode(connectorID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(ConnectorResource.class).path("{connectorID}").build(connectorID);
        connectorData.setLink(new Link("self", uri));

        return connectorData;
    }

    public ConnectorRecord createConnectorRecord(ConnectorData connectorData) {

        ConnectorRecord connectorRecord = new ConnectorRecord();
        connectorRecord.setID(connectorData.getID());
        connectorRecord.setStatus(connectorData.getStatus());
        connectorRecord.setProperties(connectorData.getProperties());

        return connectorRecord;
    }

    @Override
    public Response findConnectors(String filter, Integer start, Integer size) {

        CMS.debug("ConnectorService.findConnectors()");

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            Iterator<ConnectorRecord> connections = database.findRecords(filter).iterator();

            ConnectorCollection response = new ConnectorCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && connections.hasNext(); i++) connections.next();

            // return entries up to the page size
            for ( ; i<start+size && connections.hasNext(); i++) {
                response.addEntry(createConnectorData(connections.next()));
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

            return createOKResponse(response);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getConnector(String connectorID) {

        if (connectorID == null) throw new BadRequestException("Connector ID is null.");

        CMS.debug("ConnectorService.getConnector(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            return createOKResponse(createConnectorData(database.getRecord(connectorID)));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addConnector(ConnectorData connectorData) {

        if (connectorData == null) throw new BadRequestException("Connector data is null.");

        CMS.debug("ConnectorService.addConnector(\"" + connectorData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            database.addRecord(connectorData.getID(), createConnectorRecord(connectorData));
            connectorData = createConnectorData(database.getRecord(connectorData.getID()));

            return createCreatedResponse(connectorData, connectorData.getLink().getHref());

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response updateConnector(String connectorID, ConnectorData connectorData) {

        if (connectorID == null) throw new BadRequestException("Connector ID is null.");
        if (connectorData == null) throw new BadRequestException("Connector data is null.");

        CMS.debug("ConnectorService.updateConnector(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            ConnectorRecord record = database.getRecord(connectorID);

            // only disabled connector can be updated
            if (!"Disabled".equals(record.getStatus())) {
                throw new ForbiddenException("Unable to update connector " + connectorID);
            }

            // update status if specified
            String status = connectorData.getStatus();
            if (status != null && !"Disabled".equals(status)) {
                if (!"Enabled".equals(status)) {
                    throw new ForbiddenException("Invalid connector status: " + status);
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = "Pending_Approval";
                }

                // enable connector
                record.setStatus(status);
            }

            // update properties if specified
            Map<String, String> properties = connectorData.getProperties();
            if (properties != null) {
                record.setProperties(properties);
            }

            database.updateRecord(connectorID, record);

            connectorData = createConnectorData(database.getRecord(connectorID));

            return createOKResponse(connectorData);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response changeConnectorStatus(String connectorID, String action) {

        if (connectorID == null) throw new BadRequestException("Connector ID is null.");
        if (action == null) throw new BadRequestException("Action is null.");

        CMS.debug("ConnectorService.changeConnectorStatus(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            ConnectorRecord record = database.getRecord(connectorID);
            String status = record.getStatus();

            if ("Disabled".equals(status)) {
                if ("enable".equals(action)) {
                    status = "Enabled";
                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else if ("Enabled".equals(status)) {
                if ("disable".equals(action)) {
                    status = "Disabled";
                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else if ("Pending_Approval".equals(status)) {
                if ("approve".equals(action)) {
                    status = "Enabled";
                } else if ("reject".equals(action)) {
                    status = "Disabled";
                } else {
                    throw new BadRequestException("Invalid action: " + action);
                }

            } else {
                throw new PKIException("Invalid connector status: " + status);
            }

            record.setStatus(status);
            database.updateRecord(connectorID, record);

            ConnectorData connectorData = createConnectorData(database.getRecord(connectorID));

            return createOKResponse(connectorData);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response removeConnector(String connectorID) {

        if (connectorID == null) throw new BadRequestException("Connector ID is null.");

        CMS.debug("ConnectorService.removeConnector(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem)CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            ConnectorRecord record = database.getRecord(connectorID);
            String status = record.getStatus();

            if (!"Disabled".equals(status)) {
                throw new ForbiddenException("Unable to delete connector " + connectorID);
            }

            database.removeRecord(connectorID);

            return createNoContentResponse();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
