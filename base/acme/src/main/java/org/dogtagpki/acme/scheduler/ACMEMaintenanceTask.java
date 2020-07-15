//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.scheduler;

import java.util.Date;

import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.server.ACMEEngine;

/**
 * @author Endi S. Dewata
 */
public class ACMEMaintenanceTask extends ACMETask {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEMaintenanceTask.class);

    public void run() throws Exception {

        logger.info("Running ACME maintenance");

        Date currentTime = new Date();

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase database = engine.getDatabase();

        database.removeExpiredNonces(currentTime);
        database.removeExpiredAuthorizations(currentTime);
        database.removeExpiredOrders(currentTime);
    }
}
