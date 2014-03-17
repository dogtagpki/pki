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
 * This class provides access to the profiles in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class ProfileDatabase extends CSCfgDatabase<ProfileRecord> {

    public ProfileDatabase() {
        super("Profile", "Profiles");
    }

    public ProfileRecord createProfileRecord(ConfigDatabase configDatabase, ConfigRecord configRecord, String profileID) throws EBaseException {
        ProfileRecord profileRecord = new ProfileRecord();
        profileRecord.setID(profileID);

        String status = getRecordStatus(profileID);
        profileRecord.setStatus(status);

        Map<String, String> properties = configDatabase.getProperties(configRecord, profileID);
        profileRecord.setProperties(properties);

        return profileRecord;
    }

    @Override
    public Collection<ProfileRecord> findRecords(String filter) throws Exception {

        Collection<ProfileRecord> result = new ArrayList<ProfileRecord>();
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        for (String profileID : configRecord.getKeys()) {
            if (filter != null && !profileID.contains(filter)) continue;
            ProfileRecord profileRecord = createProfileRecord(configDatabase, configRecord, profileID);
            result.add(profileRecord);
        }

        return result;
    }

    @Override
    public ProfileRecord getRecord(String profileID) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        return createProfileRecord(configDatabase, configRecord, profileID);
    }

    @Override
    public void addRecord(String profileID, ProfileRecord profileRecord) throws Exception {

        CMS.debug("ProfileDatabase.addRecord(\"" + profileID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = profileRecord.getProperties();
        configDatabase.validateProperties(configRecord, profileID, properties);

        // add new profile
        configRecord.addKey(profileID);
        configDatabase.updateRecord(substoreName, configRecord);

        // store new properties
        configDatabase.addProperties(configRecord, profileID, properties);

        // create status
        createRecordStatus(profileID, profileRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void updateRecord(String profileID, ProfileRecord profileRecord) throws Exception {

        CMS.debug("ProfileDatabase.updateRecord(\"" + profileID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = profileRecord.getProperties();
        configDatabase.validateProperties(configRecord, profileID, properties);

        // remove old properties
        configDatabase.removeProperties(configRecord, profileID);

        // add new properties
        configDatabase.addProperties(configRecord, profileID, properties);

        // update status
        setRecordStatus(profileID, profileRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void removeRecord(String profileID) throws Exception {

        CMS.debug("ProfileDatabase.removeRecord(\"" + profileID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // remove properties
        configDatabase.removeProperties(configRecord, profileID);

        // remove profile
        configRecord.removeKey(profileID);
        configDatabase.updateRecord(substoreName, configRecord);

        // remove status
        removeRecordStatus(profileID);

        configDatabase.commit();
    }
}
