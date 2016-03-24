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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ConnectorDatabase;
import org.dogtagpki.server.tps.config.ConnectorRecord;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.ILogger;
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
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            Iterator<ConnectorRecord> connections = database.findRecords(filter).iterator();

            ConnectorCollection response = new ConnectorCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && connections.hasNext(); i++)
                connections.next();

            // return entries up to the page size
            for (; i < start + size && connections.hasNext(); i++) {
                response.addEntry(createConnectorData(connections.next()));
            }

            // count the total entries
            for (; connections.hasNext(); i++)
                connections.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start + size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                response.addLink(new Link("next", uri));
            }

            return createOKResponse(response);

        } catch (PKIException e) {
            CMS.debug("ConnectorService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response getConnector(String connectorID) {

        if (connectorID == null)
            throw new BadRequestException("Connector ID is null.");

        CMS.debug("ConnectorService.getConnector(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            return createOKResponse(createConnectorData(database.getRecord(connectorID)));

        } catch (PKIException e) {
            CMS.debug("ConnectorService: " + e);
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    @Override
    public Response addConnector(ConnectorData connectorData) {
        String method = "ConnectorService.addConnector";

        if (connectorData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Connector data is null.");
            throw new BadRequestException("Connector data is null.");
        }

        CMS.debug("ConnectorService.addConnector(\"" + connectorData.getID() + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            String status = connectorData.getStatus();
            Principal principal = servletRequest.getUserPrincipal();

            boolean statusChanged = false;
            if (StringUtils.isEmpty(status) || database.requiresApproval() && !database.canApprove(principal)) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                status = Constants.CFG_DISABLED;
                connectorData.setStatus(status);
                statusChanged = true;
            }

            database.addRecord(connectorData.getID(), createConnectorRecord(connectorData));
            connectorData = createConnectorData(database.getRecord(connectorData.getID()));
            Map<String, String> properties = connectorData.getProperties();
            if (statusChanged) {
                properties.put("Status", status);
            }
            auditTPSConnectorChange(ILogger.SUCCESS, method, connectorData.getID(), properties, null);

            return createCreatedResponse(connectorData, connectorData.getLink().getHref());

        } catch (PKIException e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response updateConnector(String connectorID, ConnectorData connectorData) {
        String method = "ConnectorService.updateConnector";

        if (connectorID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Connector id is null.");
            throw new BadRequestException("Connector ID is null.");
        }
        if (connectorData == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Connector data is null.");
            throw new BadRequestException("Connector data is null.");
        }

        CMS.debug("ConnectorService.updateConnector(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            ConnectorRecord record = database.getRecord(connectorID);

            // only disabled connector can be updated
            if (!Constants.CFG_DISABLED.equals(record.getStatus())) {
                Exception e = new ForbiddenException("Unable to update connector " + connectorID);
                auditTPSConnectorChange(ILogger.FAILURE, method,
                        connectorData.getID(), connectorData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = connectorData.getStatus();
            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    Exception e = new ForbiddenException("Invalid connector status: " + status);
                    auditTPSConnectorChange(ILogger.FAILURE, method,
                            connectorData.getID(), connectorData.getProperties(), e.toString());
                    throw e;
                }

                // if user doesn't have rights, set to pending
                Principal principal = servletRequest.getUserPrincipal();
                if (database.requiresApproval() && !database.canApprove(principal)) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }

                // enable connector
                record.setStatus(status);
                statusChanged = true;
            }

            // update properties if specified
            Map<String, String> properties = connectorData.getProperties();
            if (properties != null) {
                record.setProperties(properties);
                if (statusChanged) {
                    properties.put("Status", status);
                }
            }

            database.updateRecord(connectorID, record);

            connectorData = createConnectorData(database.getRecord(connectorID));
            auditTPSConnectorChange(ILogger.SUCCESS, method, connectorData.getID(), properties, null);

            return createOKResponse(connectorData);

        } catch (PKIException e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response changeStatus(String connectorID, String action) {
        String method = "ConnectorService.changeStatus";
        Map<String, String> auditModParams = new HashMap<String, String>();

        if (connectorID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Connector id is null.");
            throw new BadRequestException("Connector ID is null.");
        }
        if (action == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Action is null.");
            throw new BadRequestException("Action is null.");
        }
        auditModParams.put("Action", action);

        CMS.debug("ConnectorService.changeStatus(\"" + connectorID + "\", \"" + action + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            ConnectorRecord record = database.getRecord(connectorID);
            String status = record.getStatus();

            Principal principal = servletRequest.getUserPrincipal();
            boolean canApprove = database.canApprove(principal);

            if (Constants.CFG_DISABLED.equals(status)) {

                if (database.requiresApproval()) {

                    if ("submit".equals(action) && !canApprove) {
                        status = Constants.CFG_PENDING_APPROVAL;

                    } else if ("enable".equals(action) && canApprove) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditConfigTokenGeneral(ILogger.FAILURE, method,
                                auditModParams, e.toString());
                        auditTPSConnectorChange(ILogger.FAILURE, method,
                                connectorID, auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSConnectorChange(ILogger.FAILURE, method,
                                connectorID, auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSConnectorChange(ILogger.FAILURE, method,
                            connectorID, auditModParams, e.toString());
                    throw e;
                }

            } else if (Constants.CFG_PENDING_APPROVAL.equals(status)) {

                if ("approve".equals(action) && canApprove) {
                    status = Constants.CFG_ENABLED;

                } else if ("reject".equals(action) && canApprove) {
                    status = Constants.CFG_DISABLED;

                } else if ("cancel".equals(action) && !canApprove) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSConnectorChange(ILogger.FAILURE, method,
                            connectorID, auditModParams, e.toString());
                    throw e;
                }

            } else {
                Exception e = new BadRequestException("Invalid connector status: " + status);
                auditTPSConnectorChange(ILogger.FAILURE, method,
                        connectorID, auditModParams, e.toString());
                throw e;
            }

            record.setStatus(status);
            database.updateRecord(connectorID, record);

            ConnectorData connectorData = createConnectorData(database.getRecord(connectorID));
            auditModParams.put("Status", status);
            auditTPSConnectorChange(ILogger.SUCCESS, method, connectorData.getID(), auditModParams, null);

            return createOKResponse(connectorData);

        } catch (PKIException e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    @Override
    public Response removeConnector(String connectorID) {
        String method = "ConnectorService.removeConnector";
        Map<String, String> auditModParams = new HashMap<String, String>();

        if (connectorID == null) {
            auditConfigTokenGeneral(ILogger.FAILURE, method, null,
                    "Connector ID is null.");
            throw new BadRequestException("Connector ID is null.");
        }
        auditModParams.put("connectorID", connectorID);

        CMS.debug("ConnectorService.removeConnector(\"" + connectorID + "\")");

        try {
            TPSSubsystem subsystem = (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
            ConnectorDatabase database = subsystem.getConnectorDatabase();

            ConnectorRecord record = database.getRecord(connectorID);
            String status = record.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Unable to delete connector "
                        + connectorID
                        + "; connector not disabled");
                auditTPSConnectorChange(ILogger.FAILURE, method,
                        connectorID, auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(connectorID);
            auditTPSConnectorChange(ILogger.SUCCESS, method, connectorID, null, null);

            return createNoContentResponse();

        } catch (PKIException e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            CMS.debug("ConnectorService: " + e);
            auditTPSConnectorChange(ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    /*
     * service can be any of the methods offered
     */
    public void auditTPSConnectorChange(String status, String service, String connectorID, Map<String, String> params,
            String info) {

        String msg = CMS.getLogMessage(
                "LOGGING_SIGNED_AUDIT_CONFIG_TOKEN_CONNECTOR_6",
                servletRequest.getUserPrincipal().getName(),
                status,
                service,
                connectorID,
                auditor.getParamString(null, params),
                info);
        auditor.log(msg);

    }
}
