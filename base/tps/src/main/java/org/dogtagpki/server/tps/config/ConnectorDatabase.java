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

package org.dogtagpki.server.tps.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.CSCfgDatabase;

/**
 * This class provides access to the connections in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class ConnectorDatabase extends CSCfgDatabase<ConnectorRecord> {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConnectorDatabase.class);

    public String prefix = "tps.connector";

    public ConnectorDatabase() {
        super("Connector", "Subsystem_Connections");
    }

    public ConnectorRecord createConnectorRecord(ConfigDatabase configDatabase, ConfigRecord configRecord, String connectorID) throws EBaseException {
        ConnectorRecord connectorRecord = new ConnectorRecord();
        connectorRecord.setID(connectorID);

        String status = getRecordStatus(connectorID);
        connectorRecord.setStatus(status);

        Map<String, String> properties = configDatabase.getProperties(configRecord, connectorID);
        connectorRecord.setProperties(properties);
        return connectorRecord;
    }

    @Override
    public Collection<ConnectorRecord> findRecords(String filter) throws Exception {

        Collection<ConnectorRecord> result = new ArrayList<>();
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        for (String connectorID : configRecord.getKeys()) {
            if (filter != null && !connectorID.contains(filter)) continue;
            ConnectorRecord connectorRecord = createConnectorRecord(configDatabase, configRecord, connectorID);
            result.add(connectorRecord);
        }

        return result;
    }

    @Override
    public ConnectorRecord getRecord(String connectionID) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        return createConnectorRecord(configDatabase, configRecord, connectionID);
    }

    @Override
    public void addRecord(String connectorID, ConnectorRecord connectorRecord) throws Exception {

        logger.debug("ConnectorDatabase.addRecord(\"" + connectorID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = connectorRecord.getProperties();
        configDatabase.validateProperties(configRecord, connectorID, properties);

        // add new connector
        configRecord.addKey(connectorID);
        configDatabase.updateRecord(substoreName, configRecord);

        // store new properties
        configDatabase.addProperties(configRecord, connectorID, properties);

        // create status
        setRecordStatus(connectorID, connectorRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void updateRecord(String connectorID, ConnectorRecord connectorRecord) throws Exception {

        logger.debug("ConnectorDatabase.updateRecord(\"" + connectorID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = connectorRecord.getProperties();
        configDatabase.validateProperties(configRecord, connectorID, properties);

        // remove old properties
        configDatabase.removeProperties(configRecord, connectorID);

        // add new properties
        configDatabase.addProperties(configRecord, connectorID, properties);

        // update status
        setRecordStatus(connectorID, connectorRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void removeRecord(String connectorID) throws Exception {

        logger.debug("ConnectorDatabase.removeRecord(\"" + connectorID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // remove properties
        configDatabase.removeProperties(configRecord, connectorID);

        // remove connector
        configRecord.removeKey(connectorID);
        configDatabase.updateRecord(substoreName, configRecord);

        // remove status
        removeRecordStatus(connectorID);

        configDatabase.commit();
    }

    public String getNextID(String type) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);
        Collection<String> keys = configRecord.getKeys();

        String id;
        int n = 1;

        while (true) {
            id = type + n;

            if (keys.contains(id)) {
                // ID is already used, find the next one.
                n++;

            } else {
                // ID is available, use this one.
                break;
            }
        }

        return id;
    }
}
