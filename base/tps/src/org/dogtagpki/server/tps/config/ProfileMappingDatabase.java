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
 * This class provides access to the profileMappings in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class ProfileMappingDatabase extends CSCfgDatabase<ProfileMappingRecord> {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileMappingDatabase.class);

    public ProfileMappingDatabase() {
        super("Profile Mapping", "Profile_Mappings");
    }

    public ProfileMappingRecord createProfileMappingRecord(ConfigDatabase configDatabase, ConfigRecord configRecord, String profileMappingID) throws EBaseException {
        ProfileMappingRecord profileMappingRecord = new ProfileMappingRecord();
        profileMappingRecord.setID(profileMappingID);

        String status = getRecordStatus(profileMappingID);
        profileMappingRecord.setStatus(status);

        Map<String, String> properties = configDatabase.getProperties(configRecord, profileMappingID);
        profileMappingRecord.setProperties(properties);
        return profileMappingRecord;
    }

    @Override
    public Collection<ProfileMappingRecord> findRecords(String filter) throws Exception {

        Collection<ProfileMappingRecord> result = new ArrayList<ProfileMappingRecord>();
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        for (String profileMappingID : configRecord.getKeys()) {
            if (filter != null && !profileMappingID.contains(filter)) continue;
            ProfileMappingRecord profileMappingRecord = createProfileMappingRecord(configDatabase, configRecord, profileMappingID);
            result.add(profileMappingRecord);
        }

        return result;
    }

    @Override
    public ProfileMappingRecord getRecord(String profileMappingID) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        return createProfileMappingRecord(configDatabase, configRecord, profileMappingID);
    }


    @Override
    public void addRecord(String profileMappingID, ProfileMappingRecord profileMappingRecord) throws Exception {

        logger.debug("ProfileMappingDatabase.addRecord(\"" + profileMappingID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = profileMappingRecord.getProperties();
        configDatabase.validateProperties(configRecord, profileMappingID, properties);

        // add new profileMapping
        configRecord.addKey(profileMappingID);
        configDatabase.updateRecord(substoreName, configRecord);

        // store new properties
        configDatabase.addProperties(configRecord, profileMappingID, properties);

        // create status
        setRecordStatus(profileMappingID, profileMappingRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void updateRecord(String profileMappingID, ProfileMappingRecord profileMappingRecord) throws Exception {

        logger.debug("ProfileMappingDatabase.updateRecord(\"" + profileMappingID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // validate new properties
        Map<String, String> properties = profileMappingRecord.getProperties();
        configDatabase.validateProperties(configRecord, profileMappingID, properties);

        // remove old properties
        configDatabase.removeProperties(configRecord, profileMappingID);

        // add new properties
        configDatabase.addProperties(configRecord, profileMappingID, properties);

        // update status
        setRecordStatus(profileMappingID, profileMappingRecord.getStatus());

        configDatabase.commit();
    }

    @Override
    public void removeRecord(String profileMappingID) throws Exception {

        logger.debug("ProfileMappingDatabase.removeRecord(\"" + profileMappingID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord(substoreName);

        // remove properties
        configDatabase.removeProperties(configRecord, profileMappingID);

        // remove profileMapping
        configRecord.removeKey(profileMappingID);
        configDatabase.updateRecord(substoreName, configRecord);

        // remove status
        removeRecordStatus(profileMappingID);

        configDatabase.commit();
    }
}
