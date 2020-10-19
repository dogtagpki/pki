//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.database;

/**
 * @author Endi S. Dewata
 */
public class PostgreSQLConfigMonitor implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PostgreSQLConfigMonitor.class);

    public final static int DEFAULT_INTERVAL = 5; // minutes

    PostgreSQLDatabase database;
    int interval = DEFAULT_INTERVAL;
    boolean running;

    public PostgreSQLConfigMonitor() {
    }

    public PostgreSQLDatabase getDatabase() {
        return database;
    }

    public void setDatabase(PostgreSQLDatabase database) {
        this.database = database;
    }

    public int getInterval() {
        return interval;
    }

    public void setInterval(int interval) {
        this.interval = interval;
    }

    public void run() {

        logger.info("Start monitoring ACME configuration");

        running = true;

        while (running) {
            try {
                database.connect();

                logger.info("Updating ACME configuration");
                // update the config in memory only

                String value = database.getConfig("enabled");
                database.enabled = value == null ? null : Boolean.valueOf(value);
                logger.info("- enabled: " + database.enabled);

            } catch (Exception e) {
                logger.error("Unable to monitor ACME configuration: " + e.getMessage(), e);
            }

            try {
                Thread.sleep(interval * 60 * 1000);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }

        logger.info("Stop monitoring ACME configuration");
    }

    public void stop() throws Exception {
        running = false; // terminate the loop gracefully
    }
}
