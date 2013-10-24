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

package org.dogtagpki.server.tps.profile;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.tps.config.ConfigDatabase;
import org.dogtagpki.server.tps.config.ConfigRecord;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.dbs.Database;

/**
 * This class provides access to the profiles in CS.cfg.
 *
 * @author Endi S. Dewata
 */
public class ProfileDatabase extends Database<ProfileRecord> {

    IConfigStore configStore = CMS.getConfigStore();

    public ProfileDatabase() {
        super("Profile");
    }

    public boolean requiresApproval() throws EBaseException {
        String value = configStore.getString("target.agent_approve.list", "");
        return Arrays.asList(StringUtils.split(value, ",")).contains("Profiles");
    }

    public boolean canApprove(Principal principal) {
        if (!(principal instanceof PKIPrincipal)) {
            return false;
        }

        PKIPrincipal pkiPrincipal = (PKIPrincipal)principal;
        return pkiPrincipal.hasRole("TUS Agents");
    }

    public ProfileRecord createProfileRecord(ConfigDatabase configDatabase, ConfigRecord configRecord, String profileID) throws EBaseException {
        ProfileRecord profileRecord = new ProfileRecord();
        profileRecord.setID(profileID);

        String status = configStore.getString("config.Profiles." + profileID + ".state", "Disabled");
        profileRecord.setStatus(status);

        Map<String, String> properties = configDatabase.getProperties(configRecord, profileID);
        profileRecord.setProperties(properties);

        return profileRecord;
    }

    @Override
    public Collection<ProfileRecord> getRecords() throws Exception {

        Collection<ProfileRecord> result = new ArrayList<ProfileRecord>();
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Profiles");

        for (String profileID : configRecord.getKeys()) {
            ProfileRecord profileRecord = createProfileRecord(configDatabase, configRecord, profileID);
            result.add(profileRecord);
        }

        return result;
    }

    @Override
    public ProfileRecord getRecord(String profileID) throws Exception {

        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Profiles");

        return createProfileRecord(configDatabase, configRecord, profileID);
    }

    @Override
    public void addRecord(String profileID, ProfileRecord profileRecord) throws Exception {

        CMS.debug("ProfileDatabase.addRecord(\"" + profileID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Profiles");

        // validate new properties
        Map<String, String> properties = profileRecord.getProperties();
        configDatabase.validateProperties(configRecord, profileID, properties);

        // add new profile
        configRecord.addKey(profileID);
        configDatabase.updateRecord("Profiles", configRecord);

        // store new properties
        configDatabase.addProperties(configRecord, profileID, properties);

        // store status
        String status = profileRecord.getStatus();
        if (status == null || requiresApproval()) {
            status = "Disabled";
        }

        IConfigStore configStore = CMS.getConfigStore();
        configStore.put("config.Profiles." + profileID + ".state", status);
        configStore.put("config.Profiles." + profileID + ".timestamp", "" + (System.currentTimeMillis() * 1000));

        configDatabase.commit();
    }

    @Override
    public void updateRecord(String profileID, ProfileRecord profileRecord) throws Exception {

        CMS.debug("ProfileDatabase.updateRecord(\"" + profileID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Profiles");

        // validate new properties
        Map<String, String> properties = profileRecord.getProperties();
        configDatabase.validateProperties(configRecord, profileID, properties);

        // remove old properties
        configDatabase.removeProperties(configRecord, profileID);

        // add new properties
        configDatabase.addProperties(configRecord, profileID, properties);

        IConfigStore configStore = CMS.getConfigStore();
        configStore.put("config.Profiles." + profileID + ".state", profileRecord.getStatus());
        configStore.put("config.Profiles." + profileID + ".timestamp", "" + (System.currentTimeMillis() * 1000));

        configDatabase.commit();
    }

    @Override
    public void removeRecord(String profileID) throws Exception {

        CMS.debug("ProfileDatabase.removeRecord(\"" + profileID + "\")");
        ConfigDatabase configDatabase = new ConfigDatabase();
        ConfigRecord configRecord = configDatabase.getRecord("Profiles");

        // remove properties
        configDatabase.removeProperties(configRecord, profileID);

        // remove profile
        configRecord.removeKey(profileID);
        configDatabase.updateRecord("Profiles", configRecord);

        IConfigStore configStore = CMS.getConfigStore();
        configStore.remove("config.Profiles." + profileID + ".state");
        configStore.remove("config.Profiles." + profileID + ".timestamp");

        configDatabase.commit();
    }
}
