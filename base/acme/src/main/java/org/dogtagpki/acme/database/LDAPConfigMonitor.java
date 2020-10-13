//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.controls.LDAPPersistSearchControl;

/**
 * @author Endi S. Dewata
 */
public class LDAPConfigMonitor implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPConfigMonitor.class);

    LDAPDatabase database;
    LDAPPersistSearchControl searchControl;
    boolean running;

    public LDAPConfigMonitor() {
        searchControl = new LDAPPersistSearchControl(
                LDAPPersistSearchControl.MODIFY,
                false, // return initial entry and subsequent changes
                true,  // return controls
                true); // persistent search control is critical
    }

    public LDAPDatabase getDatabase() {
        return database;
    }

    public void setDatabase(LDAPDatabase database) {
        this.database = database;
    }

    public void run() {

        running = true;

        while (running) { // restart persistent search in case it's interrupted

            LDAPConnection conn = null;
            try {
                conn = database.connFactory.getConn();

                LDAPSearchConstraints searchConstraints = conn.getSearchConstraints();
                searchConstraints.setServerControls(searchControl);
                searchConstraints.setBatchSize(1);
                searchConstraints.setServerTimeLimit(0);

                logger.info("Start monitoring ACME configuration");

                LDAPSearchResults results = conn.search(
                        LDAPDatabase.RDN_CONFIG + "," + database.baseDN,
                        LDAPConnection.SCOPE_BASE,
                        "(objectClass=*)",
                        null,  // return all attributes
                        false, // return attribute values
                        searchConstraints);

                while (running && results.hasMoreElements()) { // process config updates

                    LDAPEntry entry = results.next();
                    logger.info("Updating ACME configuration");

                    // update the config in memory only

                    LDAPAttribute acmeEnabled = entry.getAttribute(LDAPDatabase.ATTR_ENABLED);
                    if (acmeEnabled == null) {
                        database.enabled = null;
                    } else {
                        String value = acmeEnabled.getStringValueArray()[0];
                        database.enabled = Boolean.parseBoolean(value);
                    }

                    logger.info("- enabled: " + database.enabled);
                }

                logger.info("Stop monitoring ACME configuration");

            } catch (Throwable e) {
                logger.error("Unable to monitor ACME configuration: " + e.getMessage(), e);
                try {
                    Thread.sleep(10 * 1000); // wait 10s then restart persistent search
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }

            } finally {
                if (conn != null) {
                    database.connFactory.returnConn(conn);
                }
            }
        }
    }

    public void stop() throws Exception {
        running = false; // terminate the loop gracefully
    }
}
