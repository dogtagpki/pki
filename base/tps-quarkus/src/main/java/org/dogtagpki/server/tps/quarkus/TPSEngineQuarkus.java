//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.User;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * CDI-managed wrapper for TPSEngine in Quarkus deployments.
 *
 * TPS extends CMSEngine and needs the full PKI infrastructure
 * (LDAP, auth, authz, token databases, connectors, etc.).
 * This wrapper manages the real TPSEngine lifecycle via CDI events
 * and replaces Tomcat-specific components with Quarkus equivalents.
 *
 * Provides utility methods for profile-based authorization and
 * audit logging that replace the TPSServlet base class methods.
 */
@ApplicationScoped
public class TPSEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(TPSEngineQuarkus.class);

    private static TPSEngineQuarkus INSTANCE;

    private TPSEngine engine;

    public static TPSEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public TPSEngine getEngine() {
        return engine;
    }

    public TPSSubsystem getSubsystem() {
        return (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start TPS engine", e);
            throw new RuntimeException("TPS engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping TPS engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("TPSEngineQuarkus: Starting TPS engine");

        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        engine = new TPSEngine();
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());
        engine.start();

        logger.info("TPSEngineQuarkus: TPS engine started successfully");
    }

    public void stop() throws Exception {
        logger.info("TPSEngineQuarkus: Stopping TPS engine");

        if (engine != null) {
            engine.stop();
            engine = null;
        }

        logger.info("TPSEngineQuarkus: TPS engine stopped");
    }

    /**
     * Convert a Quarkus SecurityIdentity to a PKIPrincipal.
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

        String name = identity.getPrincipal().getName();
        User user = new User();
        user.setUserID(name);
        user.setFullName(name);
        return new PKIPrincipal(user, null, List.of(), null);
    }

    /**
     * Get the list of TPS profiles authorized for the current user.
     * Replaces TPSServlet.getAuthorizedProfiles().
     *
     * In Tomcat, this reads from SessionContext populated during authentication.
     * In Quarkus, we extract the User from the SecurityIdentity's PKIPrincipalCore
     * and read TPS profiles from the user record.
     */
    public static List<String> getAuthorizedProfiles(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            User user = (User) core.getUser();
            if (user != null) {
                List<String> profiles = user.getTpsProfiles();
                if (profiles != null && !profiles.isEmpty()) {
                    return profiles;
                }
            }
        }

        // Fallback: grant ALL_PROFILES for authenticated users without
        // explicit profile restrictions. In production, the identity
        // provider should populate TPS profiles from LDAP user attributes.
        return List.of(UserResource.ALL_PROFILES);
    }

    /**
     * Get the user ID from the SecurityIdentity for audit logging.
     */
    public static String getUserID(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core.getName();
        }
        return identity.getPrincipal().getName();
    }

    // Audit utility methods replacing TPSServlet audit methods

    public void auditConfigTokenGeneral(String status, String service,
            Map<String, String> params, String info, String userID) {
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_GENERAL,
                userID,
                status,
                service,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }

    public void auditConfigTokenRecord(String status, String service,
            String tokenID, Map<String, String> params, String info, String userID) {
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_RECORD,
                userID,
                status,
                service,
                tokenID,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }

    public void auditTokenStateChange(String status, TokenStatus oldState,
            TokenStatus newState, String oldReason, String newReason,
            Map<String, String> params, String info, String userID) {
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.TOKEN_STATE_CHANGE,
                userID,
                status,
                (oldState == null) ? "" : oldState.toString(),
                oldReason,
                (newState == null) ? "" : newState.toString(),
                newReason,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
