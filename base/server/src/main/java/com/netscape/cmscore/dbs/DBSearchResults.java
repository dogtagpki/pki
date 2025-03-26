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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.dbs;

import java.util.Enumeration;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchResults;

/**
 * A class represents the search results. A search
 * results object contain a enumeration of
 * Java objects that are just read from the database.
 *
 * @author thomask
 */
public class DBSearchResults {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DBSearchResults.class);

    private DBRegistry mRegistry = null;
    private LDAPSearchResults mRes;

    /**
     * Constructs search results.
     */
    public DBSearchResults(DBRegistry registry, LDAPSearchResults res) {
        mRegistry = registry;
        mRes = res;
    }

    /**
     * Checks if any element is available.
     */
    public boolean hasMoreElements() {
        return mRes.hasMoreElements();
    }

    /**
     * Retrieves next element.
     */
    public Object nextElement() {

        try {
            LDAPEntry entry = mRes.next();
            logger.info("DBSearchResults: - " + entry.getDN());

            LDAPAttributeSet attrs = entry.getAttributeSet();
            for (Enumeration<LDAPAttribute> e = attrs.getAttributes(); e.hasMoreElements(); ) {
                LDAPAttribute attr = e.nextElement();
                logger.debug("DBSearchResults:   - " + attr.getName());
            }

            return mRegistry.createObject(attrs);

        } catch (Exception e) {

            /*LogDoc
             *
             * @phase local ldap search
             * @reason failed to get next element
             * @message DBSearchResults: <exception thrown>
             */
            logger.warn("DBSearchResults: " + e.getMessage(), e);
        }
        return null;
    }
}
