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

package com.netscape.cmscore.dbs;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class implements in-memory database.
 *
 * @author Endi S. Dewata
 */
public class Database<E> {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Database.class);
    public final static int DEFAULT_SIZE = 20;

    public String name;

    public Map<String, E> records = new LinkedHashMap<String, E>();

    public Database(String name) {
        this.name = name;

        logger.debug("Initializing " + name + " database");
    }

    /**
     * Find records matching filter
     */
    public Collection<E> findRecords(String filter) throws Exception {

        Collection<E> results = new ArrayList<E>();
        for (String id : records.keySet()) {
            if (filter != null && !id.contains(filter)) continue;
            results.add(records.get(id));
        }

        return results;
    }

    public E getRecord(String id) throws Exception {
        if (!records.containsKey(id)) {
            throw new Exception(name + " " + id + " does not exist.");
        }
        return records.get(id);
    }

    public void addRecord(String id, E record) throws Exception {
        if (records.containsKey(id)) {
            throw new Exception(name + " " + id + " already exists.");
        }
        records.put(id, record);
    }

    public void updateRecord(String id, E record) throws Exception {
        if (!records.containsKey(id)) {
            throw new Exception(name + " " + id + " does not exist.");
        }
        records.put(id, record);
    }

    public void removeRecord(String id) throws Exception {
        if (!records.containsKey(id)) {
            throw new Exception(name + " " + id + " does not exist.");
        }
        records.remove(id);
    }
}
