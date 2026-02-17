//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;
import com.netscape.cmscore.usrgrp.User;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * CDI-managed wrapper for KRAEngine in Quarkus deployments.
 *
 * KRA extends CMSEngine and needs the full PKI infrastructure
 * (LDAP, auth, authz, key storage, etc.). This wrapper manages
 * the real KRAEngine lifecycle via CDI events and replaces
 * Tomcat-specific components with Quarkus equivalents.
 */
@ApplicationScoped
public class KRAEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(KRAEngineQuarkus.class);

    private static KRAEngineQuarkus INSTANCE;

    private KRAEngine engine;

    public static KRAEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public KRAEngine getEngine() {
        return engine;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start KRA engine", e);
            throw new RuntimeException("KRA engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping KRA engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("KRAEngineQuarkus: Starting KRA engine");

        // Configure instance directory for Quarkus
        // (replaces Tomcat's catalina.base with pki.instance.dir)
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Create the real KRA engine
        engine = new KRAEngine();

        // Replace TomcatSocketListenerRegistry with Quarkus version
        // to avoid TomcatJSS dependency at runtime
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("KRAEngineQuarkus: KRA engine started successfully");
    }

    public void stop() throws Exception {
        logger.info("KRAEngineQuarkus: Stopping KRA engine");

        if (engine != null) {
            engine.stop();
            engine = null;
        }

        logger.info("KRAEngineQuarkus: KRA engine stopped");
    }

    /**
     * Convert a Quarkus SecurityIdentity to a PKIPrincipal for use
     * with KRA processors that require Tomcat-specific principal types.
     *
     * The KeyProcessor and KeyRequestProcessor classes use
     * {@code instanceof PKIPrincipal} to extract AuthToken for
     * realm-based authorization. This method bridges the Quarkus
     * security model to the expected PKIPrincipal.
     *
     * @param identity the Quarkus SecurityIdentity
     * @return a PKIPrincipal wrapping the identity information
     */
    public static PKIPrincipal toPKIPrincipal(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            User user = (User) core.getUser();
            AuthToken authToken = (AuthToken) core.getAuthToken();
            List<String> roles = core.getRolesList();

            if (user != null) {
                return new PKIPrincipal(user, core.getPassword(), roles, authToken);
            }

            // Create a minimal User for the principal name
            User minimalUser = new User();
            minimalUser.setUserID(core.getName());
            minimalUser.setFullName(core.getName());
            return new PKIPrincipal(minimalUser, core.getPassword(), roles, authToken);
        }

        // Fallback: create from basic principal
        String name = identity.getPrincipal().getName();
        User user = new User();
        user.setUserID(name);
        user.setFullName(name);
        return new PKIPrincipal(user, null, List.of(), null);
    }
}
