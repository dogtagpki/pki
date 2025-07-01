//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.realm.PKIRealm;
import com.netscape.cms.tomcat.ProxyRealm;

public abstract class CMSWebListener implements ServletContextListener {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSWebListener.class);

    public abstract CMSEngine createEngine();

    @Override
    public void contextInitialized(ServletContextEvent event) {

        ServletContext servletContext = event.getServletContext();

        String path = servletContext.getContextPath();
        String id;

        if ("".equals(path)) {
            id = "ROOT";
        } else {
            id = path.substring(1);
        }

        CMSEngine engine = createEngine();
        engine.setID(id);
        servletContext.setAttribute("engine", engine);

        String name = engine.getName();

        try {
            engine.start();

        } catch (Exception e) {
            logger.error("Unable to start " + name + " engine: " + e.getMessage(), e);
            engine.shutdown();
            throw new PKIException("Unable to start " + name + " engine: " + e.getMessage(), e);
        }

        // Register realm for this subsystem
        PKIRealm realm = new PKIRealm();
        realm.setCMSEngine(engine);

        ProxyRealm.registerRealm(id, realm);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {

        ServletContext servletContext = event.getServletContext();

        CMSEngine engine = (CMSEngine) servletContext.getAttribute("engine");
        engine.shutdown();
    }
}
