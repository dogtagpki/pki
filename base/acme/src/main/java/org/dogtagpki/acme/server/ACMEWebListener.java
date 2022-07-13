//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import com.netscape.certsrv.base.PKIException;

@WebListener
public class ACMEWebListener implements ServletContextListener {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEWebListener.class);

    public ACMEEngine createEngine() {
        return new ACMEEngine();
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {

        String path = event.getServletContext().getContextPath();
        String id;

        if ("".equals(path)) {
            id = "ROOT";
        } else {
            id = path.substring(1);
        }

        ACMEEngine engine = createEngine();
        engine.setID(id);

        try {
            engine.start();

        } catch (Exception e) {
            logger.error("Unable to start ACME engine: " + e.getMessage(), e);
            throw new PKIException("Unable to start ACME engine: " + e.getMessage(), e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {

        ACMEEngine engine = ACMEEngine.getInstance();

        try {
            engine.stop();

        } catch (Exception e) {
            logger.error("Unable to stop ACME engine: " + e.getMessage(), e);
            throw new PKIException("Unable to stop ACME engine: " + e.getMessage(), e);
        }
    }
}
