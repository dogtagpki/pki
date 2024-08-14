//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.base;

import java.security.Principal;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.config.ConnectorDatabase;
import org.dogtagpki.server.tps.config.ConnectorRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.tps.connector.ConnectorCollection;
import com.netscape.certsrv.tps.connector.ConnectorData;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class ConnectorProcessor {
    private static final Logger logger = LoggerFactory.getLogger(ConnectorProcessor.class);

    private TPSSubsystem subsystem;
    private ConnectorDatabase database;
    private Auditor auditor;

    public ConnectorProcessor(TPSEngine engine) {
        subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
        database = subsystem.getConnectorDatabase();
        auditor = engine.getAuditor();
    }

    public ConnectorCollection findConnectors(String filter, int start, int size) {
        logger.info("ConnectorProcessor: Finding connectors");

        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }
        try {

            logger.info("ConnectorProcessor: Results:");
            Iterator<ConnectorRecord> connections = database.findRecords(filter).iterator();

            ConnectorCollection response = new ConnectorCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && connections.hasNext(); i++)
                connections.next();

            // return entries up to the page size
            for (; i < start + size && connections.hasNext(); i++) {
                ConnectorRecord connRecord = connections.next();
                logger.info("ConnectorProcessor: - {}", connRecord.getID());
                response.addEntry(createConnectorData(connRecord));
            }

            // count the total entries
            for (; connections.hasNext(); i++)
                connections.next();
            response.setTotal(i);

            return response;

        } catch (PKIException e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public ConnectorData addConnector(Principal principal, ConnectorData connectorData) {
        String method = "ConnectorProcessor.addConnector";

        if (connectorData == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Connector data is null.");
            throw new BadRequestException("Connector data is null.");
        }

        logger.info("ConnectorProcessor: Adding connector {}", connectorData.getID());

        try {

            boolean requiresApproval = database.requiresApproval();
            logger.info("ConnectorProcessor: - requires approval: {}", requiresApproval);

            String status = connectorData.getStatus();
            boolean canApprove = database.canApprove(principal);
            logger.info("ConnectorProcessor: - can approve: {}", canApprove);

            boolean statusChanged = false;
            if (StringUtils.isEmpty(status) || requiresApproval && !canApprove) {
                // if status is unspecified or user doesn't have rights to approve, the entry is disabled
                status = Constants.CFG_DISABLED;
                connectorData.setStatus(status);
                statusChanged = true;
            }

            logger.info("ConnectorProcessor: - status: {}", status);

            database.addRecord(connectorData.getID(), createConnectorRecord(connectorData));
            connectorData = createConnectorData(database.getRecord(connectorData.getID()));
            Map<String, String> properties = connectorData.getProperties();
            if (statusChanged) {
                properties.put("Status", status);
            }
            auditTPSConnectorChange(principal, ILogger.SUCCESS, method, connectorData.getID(), properties, null);

            return connectorData;

        } catch (PKIException e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public ConnectorData getConnector(String connectorID) {
        logger.info("ConnectorProcessor: Retrieving connector {}", connectorID);

        if (connectorID == null)
            throw new BadRequestException("Connector ID is null.");

        try {

            return createConnectorData(database.getRecord(connectorID));

        } catch (PKIException e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public ConnectorData updateConnector(Principal principal, String connectorID, ConnectorData connectorData) {
        logger.info("ConnectorProcessor: Updating connector {}", connectorID);

        String method = "ConnectorProcessor.updateConnector";

        if (connectorID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Connector id is null.");
            throw new BadRequestException("Connector ID is null.");
        }
        if (connectorData == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Connector data is null.");
            throw new BadRequestException("Connector data is null.");
        }
        try {

            ConnectorRecord connRecord = database.getRecord(connectorID);
            String currentStatus = connRecord.getStatus();
            logger.info("ConnectorProcessor: - current status: {}", currentStatus);

            // only disabled connector can be updated
            if (!Constants.CFG_DISABLED.equals(currentStatus)) {
                Exception e = new ForbiddenException("Unable to update connector " + connectorID);
                auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                        connectorData.getID(), connectorData.getProperties(), e.toString());
                throw e;
            }

            // update status if specified
            String status = connectorData.getStatus();
            logger.info("ConnectorProcessor: - new status: {}", status);

            boolean statusChanged = false;
            if (status != null && !Constants.CFG_DISABLED.equals(status)) {
                if (!Constants.CFG_ENABLED.equals(status)) {
                    Exception e = new ForbiddenException("Invalid connector status: " + status);
                    auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                            connectorData.getID(), connectorData.getProperties(), e.toString());
                    throw e;
                }

                boolean requiresApproval = database.requiresApproval();
                logger.info("ConnectorProcessor: - requires approve: {}", requiresApproval);

                boolean canApprove = database.canApprove(principal);
                logger.info("ConnectorProcessor: - can approve: {}", canApprove);

                if (requiresApproval && !canApprove) {
                    status = Constants.CFG_PENDING_APPROVAL;
                }

                // update connector status
                connRecord.setStatus(status);
                statusChanged = true;
            }

            // update properties if specified
            Map<String, String> properties = connectorData.getProperties();
            if (properties != null) {
                connRecord.setProperties(properties);
                if (statusChanged) {
                    properties.put("Status", status);
                }
            }
            database.updateRecord(connectorID, connRecord);
            connectorData = createConnectorData(database.getRecord(connectorID));
            auditTPSConnectorChange(principal, ILogger.SUCCESS, method, connectorData.getID(), properties, null);

            return connectorData;

        } catch (PKIException e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorData.getID(), connectorData.getProperties(), e.toString());
            throw new PKIException(e);
        }
    }

    public ConnectorData changeStatus(Principal principal, String connectorID, String action) {
        logger.info("ConnectorProcessor: Changing connector {} status: {}", connectorID, action);

        String method = "ConnectorProcessor.changeStatus";
        Map<String, String> auditModParams = new HashMap<>();

        if (connectorID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Connector id is null.");
            throw new BadRequestException("Connector ID is null.");
        }
        if (action == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Action is null.");
            throw new BadRequestException("Action is null.");
        }
        auditModParams.put("Action", action);

        try {

            ConnectorRecord connRecord = database.getRecord(connectorID);
            String status = connRecord.getStatus();

            boolean canApprove = database.canApprove(principal);
            logger.info("ConnectorProcessor: - can approve: {}", canApprove);

            logger.info("ConnectorProcessor: - current status: {}", status);
            if (Constants.CFG_DISABLED.equals(status)) {

                boolean requiresApproval = database.requiresApproval();
                logger.info("ConnectorProcessor: - requires approval: {}", requiresApproval);

                if (requiresApproval) {

                    if ("submit".equals(action) && !canApprove) {
                        status = Constants.CFG_PENDING_APPROVAL;

                    } else if ("enable".equals(action) && canApprove) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditConfigTokenGeneral(principal, ILogger.FAILURE, method,
                                auditModParams, e.toString());
                        auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                                connectorID, auditModParams, e.toString());
                        throw e;
                    }

                } else {
                    if ("enable".equals(action)) {
                        status = Constants.CFG_ENABLED;

                    } else {
                        Exception e = new BadRequestException("Invalid action: " + action);
                        auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                                connectorID, auditModParams, e.toString());
                        throw e;
                    }
                }

            } else if (Constants.CFG_ENABLED.equals(status)) {

                if ("disable".equals(action)) {
                    status = Constants.CFG_DISABLED;

                } else {
                    Exception e = new BadRequestException("Invalid action: " + action);
                    auditTPSConnectorChange(principal, ILogger.FAILURE, method,
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
                    auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                            connectorID, auditModParams, e.toString());
                    throw e;
                }

            } else {
                Exception e = new BadRequestException("Invalid connector status: " + status);
                auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                        connectorID, auditModParams, e.toString());
                throw e;
            }

            connRecord.setStatus(status);
            database.updateRecord(connectorID, connRecord);

            ConnectorData connectorData = createConnectorData(database.getRecord(connectorID));
            auditModParams.put("Status", status);
            auditTPSConnectorChange(principal, ILogger.SUCCESS, method, connectorData.getID(), auditModParams, null);

            return connectorData;

        } catch (PKIException e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    public void removeConnector(Principal principal, String connectorID) {
        String method = "ConnectorProcessor.removeConnector";
        Map<String, String> auditModParams = new HashMap<>();

        if (connectorID == null) {
            auditConfigTokenGeneral(principal, ILogger.FAILURE, method, null,
                    "Connector ID is null.");
            throw new BadRequestException("Connector ID is null.");
        }
        auditModParams.put("connectorID", connectorID);

        logger.debug("ConnectorProcessor.removeConnector(\"{}\")", connectorID);

        try {
            ConnectorRecord connRecord = database.getRecord(connectorID);
            String status = connRecord.getStatus();

            if (!Constants.CFG_DISABLED.equals(status)) {
                Exception e = new ForbiddenException("Unable to delete connector "
                        + connectorID
                        + "; connector not disabled");
                auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                        connectorID, auditModParams, e.toString());
                throw e;
            }

            database.removeRecord(connectorID);
            auditTPSConnectorChange(principal, ILogger.SUCCESS, method, connectorID, null, null);

        } catch (PKIException e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw e;

        } catch (Exception e) {
            logger.error("ConnectorProcessor: " + e.getMessage(), e);
            auditTPSConnectorChange(principal, ILogger.FAILURE, method,
                    connectorID, auditModParams, e.toString());
            throw new PKIException(e);
        }
    }

    private ConnectorData createConnectorData(ConnectorRecord connectionRecord) {
        ConnectorData connectorData = new ConnectorData();
        connectorData.setID(connectionRecord.getID());
        connectorData.setStatus(connectionRecord.getStatus());
        connectorData.setProperties(connectionRecord.getProperties());
        return connectorData;
    }

    private ConnectorRecord createConnectorRecord(ConnectorData connectorData) {

        ConnectorRecord connectorRecord = new ConnectorRecord();
        connectorRecord.setID(connectorData.getID());
        connectorRecord.setStatus(connectorData.getStatus());
        connectorRecord.setProperties(connectorData.getProperties());

        return connectorRecord;
    }

    private void auditTPSConnectorChange(Principal principal, String status, String service, String connectorID, Map<String, String> params,
            String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_CONNECTOR,
                principal.getName(),
                status,
                service,
                connectorID,
                auditor.getParamString(params),
                info);
        auditor.log(msg);

    }

    private void auditConfigTokenGeneral(Principal principal, String status, String service, Map<String, String> params, String info) {

        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_GENERAL,
                principal.getName(),
                status,
                service,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
