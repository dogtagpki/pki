//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;

/**
 * CDI-managed wrapper for OCSPEngine in Quarkus deployments.
 *
 * Unlike ACME which has a standalone engine, OCSP extends CMSEngine
 * and needs the full PKI infrastructure (LDAP, auth, authz, etc.).
 * This wrapper manages the real OCSPEngine lifecycle via CDI events
 * and replaces Tomcat-specific components with Quarkus equivalents.
 */
@ApplicationScoped
public class OCSPEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(OCSPEngineQuarkus.class);

    private static OCSPEngineQuarkus INSTANCE;

    private OCSPEngine engine;

    public static OCSPEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public OCSPEngine getEngine() {
        return engine;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start OCSP engine", e);
            throw new RuntimeException("OCSP engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping OCSP engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("OCSPEngineQuarkus: Starting OCSP engine");

        // Configure instance directory for Quarkus
        // (replaces Tomcat's catalina.base with pki.instance.dir)
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Create the real OCSP engine
        engine = new OCSPEngine();

        // Replace TomcatSocketListenerRegistry with Quarkus version
        // to avoid TomcatJSS dependency at runtime
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("OCSPEngineQuarkus: OCSP engine started successfully");
    }

    public void stop() throws Exception {
        logger.info("OCSPEngineQuarkus: Stopping OCSP engine");

        if (engine != null) {
            engine.stop();
            engine = null;
        }

        logger.info("OCSPEngineQuarkus: OCSP engine stopped");
    }
}
