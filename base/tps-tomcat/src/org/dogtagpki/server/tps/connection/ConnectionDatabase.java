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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.dogtagpki.server.tps.config.ConfigDatabase;
import org.dogtagpki.server.tps.config.ConfigRecord;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.Database;

/**
 * This class provides access to the connections in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class ConnectionDatabase extends Database<ConnectionRecord> {

    public ConnectionDatabase() {
        super("Connection");
    }

    public ConnectionRecord createConnectionRecord(ConfigDatabase configDatabase, ConfigRecord configRecord, String connectionID) throws EBaseException {
        ConnectionRecord connectionRecord = new ConnectionRecord();
        connectionRecord.setID(connectionID);
        Map<String, String> properties = configDatabase.getProperties(configRecord, connectionID);
        connectionRecord.setProperties(properties);
        return connectionRecord;
    }

    @Override
    public Collection<ConnectionRecord> getRecords() throws Exception {

        Collection<ConnectionRecord> result = new ArrayList<ConnectionRecord>();
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Subsystem_Connections");

        for (String connectionID : configRecord.getKeys()) {
            ConnectionRecord connectionRecord = createConnectionRecord(configDatabase, configRecord, connectionID);
            result.add(connectionRecord);
        }

        return result;
    }

    @Override
    public ConnectionRecord getRecord(String connectionID) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Subsystem_Connections");

        return createConnectionRecord(configDatabase, configRecord, connectionID);
    }

    @Override
    public void addRecord(String connectionID, ConnectionRecord connectionRecord) throws Exception {

        CMS.debug("ConnectionDatabase.addRecord(\"" + connectionID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Subsystem_Connections");

        // validate new properties
        Map<String, String> properties = connectionRecord.getProperties();
        configDatabase.validateProperties(configRecord, connectionID, properties);

        // add new connection
        configRecord.addKey(connectionID);
        configDatabase.updateRecord("Subsystem_Connections", configRecord);

        // store new properties
        configDatabase.addProperties(configRecord, connectionID, properties);

        configDatabase.commit();
    }

    @Override
    public void updateRecord(String connectionID, ConnectionRecord connectionRecord) throws Exception {

        CMS.debug("ConnectionDatabase.updateRecord(\"" + connectionID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Subsystem_Connections");

        // validate new properties
        Map<String, String> properties = connectionRecord.getProperties();
        configDatabase.validateProperties(configRecord, connectionID, properties);

        // remove old properties
        configDatabase.removeProperties(configRecord, connectionID);

        // add new properties
        configDatabase.addProperties(configRecord, connectionID, properties);

        configDatabase.commit();
    }

    @Override
    public void removeRecord(String connectionID) throws Exception {

        CMS.debug("ConnectionDatabase.removeRecord(\"" + connectionID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Subsystem_Connections");

        // remove properties
        configDatabase.removeProperties(configRecord, connectionID);

        // remove connection
        configRecord.removeKey(connectionID);
        configDatabase.updateRecord("Subsystem_Connections", configRecord);

        configDatabase.commit();
    }
}
