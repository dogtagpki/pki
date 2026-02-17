package com.netscape.cms.realm;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.cmscore.usrgrp.User;

/**
 * Tomcat-specific PKI principal.
 *
 * Extends Tomcat's GenericPrincipal for compatibility with the
 * Tomcat Realm/Valve infrastructure, while delegating user and
 * auth token storage to the container-agnostic PKIPrincipalCore.
 *
 * @author Endi S. Dewata
 */
public class PKIPrincipal extends GenericPrincipal {

    private final PKIPrincipalCore core;

    public PKIPrincipal(User user, String password, List<String> roles) {
        this(user, password, roles, null);
    }

    public PKIPrincipal(User user, String password, List<String> roles, AuthToken authToken) {
        super(user.getUserID(), password, roles);
        this.core = new PKIPrincipalCore(user.getUserID(), password, roles, user, authToken);
    }

    public PKIPrincipalCore getCore() {
        return core;
    }

    public User getUser() {
        return (User) core.getUser();
    }

    public AuthToken getAuthToken() {
        return (AuthToken) core.getAuthToken();
    }
}
