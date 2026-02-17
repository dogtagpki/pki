package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.catalina.realm.RealmBase;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.usrgrp.User;

/**
 *  PKI Realm
 *
 *  This realm provides an authentication service against PKI user database.
 *  The realm also provides an authorization service that validates request
 *  URL's against the access control list defined in the internal database.
 *
 *  Authentication logic is delegated to the container-agnostic
 *  PKIAuthenticator class, which can be reused by Quarkus deployments.
 */

public class PKIRealm extends RealmBase {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIRealm.class);

    protected CMSEngine engine;
    private PKIAuthenticator authenticator;

    public PKIRealm() {
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
        this.authenticator = new PKIAuthenticator(engine);
    }

    public PKIAuthenticator getAuthenticator() {
        return authenticator;
    }

    @Override
    public Principal authenticate(String username, String password) {

        logger.info("PKIRealm: Authenticating user " + username + " with password");

        PKIPrincipalCore core = authenticator.authenticateByPassword(username, password);
        if (core == null) {
            return null;
        }

        return new PKIPrincipal(
                (User) core.getUser(),
                null,
                core.getRolesList(),
                (AuthToken) core.getAuthToken());
    }

    @Override
    public Principal authenticate(final X509Certificate[] certs) {

        logger.info("PKIRealm: Authenticating certificate chain");

        PKIPrincipalCore core = authenticator.authenticateByCertificate(certs);
        if (core == null) {
            return null;
        }

        return new PKIPrincipal(
                (User) core.getUser(),
                null,
                core.getRolesList(),
                (AuthToken) core.getAuthToken());
    }

    @Override
    protected Principal getPrincipal(String username) {

        logger.info("PKIRealm: Getting principal for " + username);

        try {
            return getPrincipal(username, (AuthToken) null);

        } catch (Exception e) {
            logger.warn("Unable to get principal for " + username + ": " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    protected Principal getPrincipal(String username, AuthToken authToken) throws Exception {
        PKIPrincipalCore core = authenticator.createPrincipal(username, authToken);
        return new PKIPrincipal(
                (User) core.getUser(),
                null,
                core.getRolesList(),
                (AuthToken) core.getAuthToken());
    }

    @Override
    protected String getPassword(String username) {
        return null;
    }
}
