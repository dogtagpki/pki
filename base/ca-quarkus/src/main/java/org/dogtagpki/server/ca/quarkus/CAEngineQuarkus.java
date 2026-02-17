//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
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
 * CDI-managed wrapper for CAEngine in Quarkus deployments.
 *
 * The CA is the most complex subsystem in Dogtag PKI, with certificate
 * issuance, revocation, CRL generation, sub-CA management, profile
 * subsystem, and security domain management. This wrapper manages the
 * real CAEngine lifecycle via CDI events and replaces Tomcat-specific
 * components with Quarkus equivalents.
 */
@ApplicationScoped
public class CAEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(CAEngineQuarkus.class);

    private static CAEngineQuarkus INSTANCE;

    private CAEngine engine;

    public static CAEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public CAEngine getEngine() {
        return engine;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start CA engine", e);
            throw new RuntimeException("CA engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping CA engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("CAEngineQuarkus: Starting CA engine");

        // Configure instance directory for Quarkus
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Create the real CA engine
        engine = new CAEngine();

        // Replace TomcatSocketListenerRegistry with Quarkus version
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("CAEngineQuarkus: CA engine started successfully");
    }

    public void stop() throws Exception {
        logger.info("CAEngineQuarkus: Stopping CA engine");

        if (engine != null) {
            engine.stop();
            engine = null;
        }

        logger.info("CAEngineQuarkus: CA engine stopped");
    }

    /**
     * Convert Quarkus SecurityIdentity to PKIPrincipal for backward
     * compatibility with processors that check instanceof PKIPrincipal.
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
            User minimalUser = new User();
            minimalUser.setUserID(core.getName());
            minimalUser.setFullName(core.getName());
            return new PKIPrincipal(minimalUser, core.getPassword(), roles, authToken);
        }
        // Fallback: create minimal principal from SecurityIdentity
        String name = identity.getPrincipal().getName();
        User user = new User();
        user.setUserID(name);
        user.setFullName(name);
        return new PKIPrincipal(user, null, List.of(), null);
    }

    /**
     * Check if the authenticated user has a specific role.
     */
    public static boolean hasRole(SecurityIdentity identity, String role) {
        return identity.getRoles().contains(role);
    }

    /**
     * Get user ID from SecurityIdentity.
     */
    public static String getUserID(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core.getName();
        }
        return identity.getPrincipal().getName();
    }
}
