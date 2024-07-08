//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

@WebListener
public class ESTWebListener implements ServletContextListener {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTWebListener.class);

    public ESTEngine createEngine() {
        return new ESTEngine();
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
        ESTEngine engine = createEngine();
        engine.setId(id);

        try {
            engine.start(event.getServletContext().getContextPath());
        } catch (Throwable e) {
            logger.error("Unable to start EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to start EST engine: " + e.getMessage(), e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        try {
            ESTEngine.getInstance().stop();
        } catch (Throwable e) {
            logger.error("Unable to stop EST engine: " + e.getMessage(), e);
            throw new RuntimeException("Unable to stop EST engine: " + e.getMessage(), e);
        }
    }
}
