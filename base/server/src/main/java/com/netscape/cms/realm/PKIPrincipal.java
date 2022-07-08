package com.netscape.cms.realm;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */

public class PKIPrincipal extends GenericPrincipal {

    User user;
    AuthToken authToken;

    public PKIPrincipal(User user, String password, List<String> roles) {
        this(user, password, roles, null);
    }

    public PKIPrincipal(User user, String password, List<String> roles, AuthToken authToken) {
        super(user.getUserID(), password, roles);
        this.user = user;
        this.authToken = authToken;
    }

    public User getUser() {
        return user;
    }

    public AuthToken getAuthToken() {
        return authToken;
    }
}
