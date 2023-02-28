//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.realm.PKIRealm;
import com.netscape.cms.tomcat.ProxyRealm;

public abstract class PKIWebListener implements ServletContextListener {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIWebListener.class);

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
        ProxyRealm.registerRealm(id, new PKIRealm());
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {

        ServletContext servletContext = event.getServletContext();

        CMSEngine engine = (CMSEngine) servletContext.getAttribute("engine");
        engine.shutdown();
    }
}
