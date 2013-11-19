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
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.cmscore.dbs.Database;

/**
 * This class implements in-memory connection database. In the future this
 * will be replaced with LDAP database.
 *
 * @author Endi S. Dewata
 */
public class ConfigDatabase extends Database<ConfigRecord> {

    IConfigStore configStore = CMS.getConfigStore();

    public ConfigDatabase() throws EBaseException {
        super("Configuration");
    }

    public String createFilter(ConfigRecord record, String key) {
        String pattern = record.getPattern();
        if (key == null) return pattern;
        return pattern.replace("$name", key);
    }

    @Override
    public Collection<ConfigRecord> getRecords() throws Exception {

        CMS.debug("ConfigDatabase.getRecords()");

        Collection<ConfigRecord> result = new ArrayList<ConfigRecord>();

        Collection<String> configIDs = new LinkedHashSet<String>();
        configIDs.add("Generals");

        String list = configStore.get("target.configure.list");
        if (list != null) {
            configIDs.addAll(Arrays.asList(list.split(",")));
        }

        list = configStore.get("target.agent_approve.list");
        if (list != null) {
            configIDs.addAll(Arrays.asList(list.split(",")));
        }

        for (String configID : configIDs) {
            ConfigRecord configData = getRecord(configID);
            result.add(configData);
        }

        return result;
    }

    @Override
    public ConfigRecord getRecord(String configID) throws Exception {

        CMS.debug("ConfigDatabase.getRecord(\"" + configID + "\")");

        ConfigRecord record = new ConfigRecord();
        record.setID(configID);

        String displayName = configStore.get("target." + configID + ".displayname");
        if (displayName == null) {
            throw new ResourceNotFoundException("Configuration " + configID + " not found.");
        }
        record.setDisplayName(displayName);

        String pattern = configStore.get("target." + configID + ".pattern");
        if (pattern == null) {
            throw new ResourceNotFoundException("Missing pattern for " + configID + " configuration.");
        }

        // replace \| with |
        record.setPattern(pattern.replace("\\|",  "|"));

        String list = configStore.get("target." + configID + ".list");
        if (list != null) {
            record.setKeys(Arrays.asList(list.split(",")));
        }

        return record;
    }


    @Override
    public void updateRecord(String configID, ConfigRecord newRecord) throws Exception {

        CMS.debug("ConfigDatabase.updateRecord(\"" + configID + "\")");

        configStore.put("target." + configID + ".displayname", newRecord.getDisplayName());
        configStore.put("target." + configID + ".pattern", newRecord.getPattern());
        configStore.put("target." + configID + ".list", StringUtils.join(newRecord.getKeys(), ","));

        configStore.commit(true);
    }

    public Map<String, String> getProperties(ConfigRecord record, String key) throws EBaseException {

        CMS.debug("ConfigDatabase.getProperties(\"" + record.getID() + "\", \"" + key + "\")");

        if (!record.containsKey(key)) {
            throw new ResourceNotFoundException("Entry does not exist: " + key);
        }

        Map<String, String> properties = new TreeMap<String, String>();

        // get properties that match the filter
        String filter = createFilter(record, key);
        Map<String, String> map = configStore.getProperties();
        for (String name : map.keySet()) {
            if (!name.matches(filter)) continue;

            String value = map.get(name);
            properties.put(name, value);
        }

        return properties;
    }

    public void validateProperties(ConfigRecord record, String key, Map<String, String> properties) throws Exception {

        CMS.debug("ConfigDatabase.validateProperties(\"" + record.getID() + "\")");

        String filter = createFilter(record, key);
        for (String name : properties.keySet()) {
            if (name.matches(filter)) continue;
            throw new BadRequestException("Invalid property: " + name);
        }
    }

    public void addProperties(ConfigRecord record, String key, Map<String, String> properties) throws Exception {

        CMS.debug("ConfigDatabase.addProperties(\"" + record.getID() + "\")");

        for (String name : properties.keySet()) {
            String value = properties.get(name);
            configStore.put(name, value);
        }
    }

    public void removeProperties(ConfigRecord record, String key) throws Exception {

        CMS.debug("ConfigDatabase.removeProperties(\"" + record.getID() + "\")");

        Map<String, String> oldProperties = getProperties(record, key);
        for (String name : oldProperties.keySet()) {
            configStore.remove(name);
        }
    }

    public void commit() throws Exception {

        CMS.debug("ConfigDatabase.commit()");

        // save configuration
        configStore.commit(true);
    }
}
