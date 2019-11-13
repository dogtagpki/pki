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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;

public class LDAPConfigurator {

    public final static Logger logger = LoggerFactory.getLogger(LDAPConfigurator.class);

    LDAPConnection connection;

    public LDAPConfigurator(LDAPConnection connection) {
        this.connection = connection;
    }

    public LDAPConnection getConnection() {
        return connection;
    }

    public LDAPEntry getEntry(String dn) throws Exception {

        logger.info("LDAPConfigurator: Getting LDAP entry " + dn);

        try {
            return connection.read(dn);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("LDAP entry not found: " + dn);
                return null;

            } else {
                String message = "Unable to get LDAP entry " + dn + ": " + e;
                logger.error(message);
                throw new Exception(message, e);
            }
        }
    }

    public void checkForConflictingMappings(String database, String baseDN) throws Exception {

        logger.info("LDAPConfigurator: Searching for mappings using database " + database);

        LDAPSearchResults res = connection.search(
                "cn=mapping tree, cn=config",
                LDAPConnection.SCOPE_ONE,
                "(nsslapd-backend=" + LDAPUtil.escapeFilter(database) + ")",
                null,
                false,
                (LDAPSearchConstraints) null);

        while (res.hasMoreElements()) {
            LDAPEntry entry = res.next();
            LDAPAttribute cn = entry.getAttribute("cn");
            String dn = cn.getStringValueArray()[0];

            if (LDAPDN.equals(dn, baseDN)) {
                continue;
            }

            String message = "Database " + database + " is used by " + dn;
            logger.error(message);
            throw new Exception(message);
        }
    }

    public void deleteEntry(String dn) throws Exception {

        try {
            LDAPSearchResults results = connection.search(
                    dn,
                    LDAPConnection.SCOPE_ONE,
                    "(objectClass=*)",
                    null,
                    true,
                    (LDAPSearchConstraints) null);

            while (results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                deleteEntry(entry.getDN());
            }

            logger.info("LDAPConfigurator: Deleting LDAP entry " + dn);
            connection.delete(dn);

        } catch (LDAPException e) {

            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                logger.warn("LDAPConfigurator: LDAP entry not found: " + dn);

            } else {
                String message = "Unable to delete " + dn + ": " + e;
                logger.error(message);
                throw new Exception(message, e);
            }
        }
    }

    public void waitForTask(String dn) throws Exception {

        String returnCode = null;
        int count = 0;
        int maxCount = 0; // TODO: make it configurable

        while (maxCount <= 0 || count < maxCount) {

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // restore the interrupted status
                Thread.currentThread().interrupt();
            }

            count++;
            logger.info("LDAPConfigurator: Waiting for task " + dn + " (" + count + "s)");

            try {
                LDAPEntry task = getEntry(dn);
                if (task == null) continue;

                LDAPAttribute attr = task.getAttribute("nsTaskExitCode");
                if (attr == null) continue;

                returnCode = attr.getStringValues().nextElement();
                break;

            } catch (Exception e) {
                logger.warn("LDAPConfigurator: Unable to read task " + dn + ": " + e);
            }
        }

        if (returnCode == null || !"0".equals(returnCode)) {
            String message = "Task " + dn + " failed: nsTaskExitCode=" + returnCode;
            logger.error(message);
            throw new Exception(message);
        }

        logger.info("LDAPConfigurator: Task " + dn + " complete");
    }

    public void createDatabaseEntry(String databaseDN, String database, String baseDN) throws Exception {

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectClass", new String[] {
                "top",
                "extensibleObject",
                "nsBackendInstance"
        }));
        attrs.add(new LDAPAttribute("cn", database));
        attrs.add(new LDAPAttribute("nsslapd-suffix", baseDN));

        LDAPEntry entry = new LDAPEntry(databaseDN, attrs);
        connection.add(entry);
    }

    public void createMappingEntry(String mappingDN, String database, String baseDN) throws Exception {

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        attrs.add(new LDAPAttribute("objectClass", new String[] {
                "top",
                "extensibleObject",
                "nsMappingTree"
        }));
        attrs.add(new LDAPAttribute("cn", baseDN));
        attrs.add(new LDAPAttribute("nsslapd-backend", database));
        attrs.add(new LDAPAttribute("nsslapd-state", "Backend"));

        LDAPEntry entry = new LDAPEntry(mappingDN, attrs);
        connection.add(entry);
    }
}
