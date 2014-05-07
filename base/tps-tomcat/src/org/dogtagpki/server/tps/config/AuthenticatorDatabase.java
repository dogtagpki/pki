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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.CSCfgDatabase;

/**
 * This class provides access to the authenticators in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class AuthenticatorDatabase extends CSCfgDatabase<AuthenticatorRecord> {

    public AuthenticatorDatabase() {
        super("Authenticator", "Authentication_Sources");
    }

    public AuthenticatorRecord createAuthenticatorRecord(ConfigDatabase configDatabase, ConfigRecord configRecord, String authenticatorID) throws EBaseException {
        AuthenticatorRecord authenticatorRecord = new AuthenticatorRecord();
        authenticatorRecord.setID(authenticatorID);

        String status = getRecordStatus(authenticatorID);
        authenticatorRecord.setStatus(status);

        Map<String, String> properties = configDatabase.getProperties(configRecord, authenticatorID);
        authenticatorRecord.setProperties(properties);
        return authenticatorRecord;
    }

    @Override
    public Collection<AuthenticatorRecord> findRecords(String filter) throws Exception {

        Collection<AuthenticatorRecord> result = new ArrayList<AuthenticatorRecord>();
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        for (String authenticatorID : configRecord.getKeys()) {
            if (filter != null && !authenticatorID.contains(filter)) continue;
            AuthenticatorRecord authenticatorRecord = createAuthenticatorRecord(configDatabase, configRecord, authenticatorID);
            result.add(authenticatorRecord);
        }

        return result;
    }

    @Override
    public AuthenticatorRecord getRecord(String authenticatorID) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        return createAuthenticatorRecord(configDatabase, configRecord, authenticatorID);
    }

    @Override
    public void addRecord(String authenticatorID, AuthenticatorRecord authenticatorRecord) throws Exception {

        CMS.debug("AuthenticatorDatabase.addRecord(\"" + authenticatorID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = authenticatorRecord.getProperties();
        configDatabase.validateProperties(configRecord, authenticatorID, properties);

        // add new connection
        configRecord.addKey(authenticatorID);
        configDatabase.updateRecord(substoreName, configRecord);

        // store new properties
        configDatabase.addProperties(configRecord, authenticatorID, properties);

        // create status
        setRecordStatus(authenticatorID, authenticatorRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void updateRecord(String authenticatorID, AuthenticatorRecord authenticatorRecord) throws Exception {

        CMS.debug("AuthenticatorDatabase.updateRecord(\"" + authenticatorID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = authenticatorRecord.getProperties();
        configDatabase.validateProperties(configRecord, authenticatorID, properties);

        // remove old properties
        configDatabase.removeProperties(configRecord, authenticatorID);

        // add new properties
        configDatabase.addProperties(configRecord, authenticatorID, properties);

        // update status
        setRecordStatus(authenticatorID, authenticatorRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void removeRecord(String authenticatorID) throws Exception {

        CMS.debug("AuthenticatorDatabase.removeRecord(\"" + authenticatorID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // remove properties
        configDatabase.removeProperties(configRecord, authenticatorID);

        // remove connection
        configRecord.removeKey(authenticatorID);
        configDatabase.updateRecord(substoreName, configRecord);

        // remove status
        removeRecordStatus(authenticatorID);

        configDatabase.commit();
    }
}
